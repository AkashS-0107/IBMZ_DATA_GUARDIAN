"""Reversible redaction engine for AI Data Leak Guardian.

Replaces detected sensitive entities with typed placeholders ([EMAIL_1], [SECRET_1])
and safely restores placeholders in AI responses using isolated in-memory session vaults.
Guarantees offset-safe replacement, collision avoidance, and session isolation.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
import uuid

from config import RedactorConfig
from detector import resolve_overlaps
from models import DetectionFinding, EntityType, RedactionResult, RestorationResult


class RedactionSession:
    """Isolated, in-memory vault and reversibility manager for a single session.

    SECURITY ARCHITECTURE:
    - In-Memory Only: Sensitive raw strings are held strictly in process memory.
    - Zero Persistence: Mappings are never written to disk, database, or logs.
    - Zero Execution: Restored text is treated as plain string data; never evaluated.
    - Demo Boundary: This is a privacy-preserving session vault designed for
      protecting prompts sent to AI systems, not a persistent enterprise HSM.
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        self.session_id: str = session_id or str(uuid.uuid4())
        # Mapping: placeholder -> raw_sensitive_value
        self._vault: Dict[str, str] = {}
        # Mapping: (entity_type, raw_value) -> placeholder (to reuse placeholders for identical values)
        self._reverse_vault: Dict[Tuple[EntityType, str], str] = {}
        # Entity counter for incremental IDs: e.g. {"EMAIL": 1, "API_KEY": 2}
        self._entity_counters: Dict[str, int] = {}

    def _next_placeholder(self, entity_type: EntityType, existing_in_text: Set[str]) -> str:
        """Generate next non-colliding placeholder for the given entity type."""
        type_str = entity_type.value
        current_idx = self._entity_counters.get(type_str, 0)

        while True:
            current_idx += 1
            candidate = RedactorConfig.PLACEHOLDER_TEMPLATE.format(
                entity_type=type_str, index=current_idx
            )
            # Avoid collision with:
            # 1. Any placeholder already defined in this session vault
            # 2. Any literal placeholder-like token already found in original user input
            if candidate not in self._vault and candidate not in existing_in_text:
                self._entity_counters[type_str] = current_idx
                return candidate

    def redact(self, text: str, findings: List[DetectionFinding]) -> RedactionResult:
        """Perform reversible redaction on text using provided findings.

        Automatically resolves any overlapping findings with secret priority, validates
        character offset boundaries, applies replacements from right to left,
        and reuses placeholders for identical sensitive values within this session.
        """
        if not text or not findings:
            return RedactionResult(
                session_id=self.session_id,
                masked_text=text or "",
                placeholders_count=0,
                unique_placeholders=0,
                findings_redacted=0,
            )

        # 1. Resolve any overlapping findings with secret priority (CRITICAL > HIGH > MEDIUM > LOW)
        clean_findings = resolve_overlaps(findings)

        # 2. Validate all finding offsets against original text length
        text_len = len(text)
        for f in clean_findings:
            if not (0 <= f.start < f.end <= text_len):
                raise ValueError(
                    f"Finding span [{f.start}, {f.end}) is out of bounds for text of length {text_len}"
                )

        # 3. Scan original text for any pre-existing literal placeholder tokens to prevent collisions
        existing_tokens = set(re.findall(r"\[[A-Z_]+_\d+\]", text))

        # 4. Sort findings right-to-left by start offset descending
        sorted_findings = sorted(clean_findings, key=lambda f: f.start, reverse=True)

        masked_text = text
        placeholders_used: List[str] = []

        for finding in sorted_findings:
            raw_val = text[finding.start:finding.end]
            cache_key = (finding.entity_type, raw_val)

            # Check if this exact entity and raw value already received a placeholder in this session
            if cache_key in self._reverse_vault:
                placeholder = self._reverse_vault[cache_key]
            else:
                placeholder = self._next_placeholder(finding.entity_type, existing_tokens)
                self._vault[placeholder] = raw_val
                self._reverse_vault[cache_key] = placeholder

            placeholders_used.append(placeholder)

            # Apply right-to-left substring replacement
            masked_text = masked_text[:finding.start] + placeholder + masked_text[finding.end:]

        return RedactionResult(
            session_id=self.session_id,
            masked_text=masked_text,
            placeholders_count=len(placeholders_used),
            unique_placeholders=len(set(placeholders_used)),
            findings_redacted=len(clean_findings),
        )

    def restore_detailed(self, ai_response: str) -> RestorationResult:
        """Safely restore placeholders in AI response text and report audit details.

        Returns a structured RestorationResult documenting restored and unrestored placeholders.
        Leaves unknown placeholders or placeholders from other sessions intact.
        Does NOT execute, evaluate, or interpret restored values.
        """
        if not ai_response:
            return RestorationResult(
                restored_text="",
                restored_placeholders=[],
                unrestored_placeholders=[],
                is_fully_restored=True,
            )

        restored_placeholders: List[str] = []
        unrestored_placeholders: List[str] = []

        def _replace_placeholder(match: re.Match) -> str:
            token = match.group(0)
            if token in self._vault:
                restored_placeholders.append(token)
                return self._vault[token]
            else:
                unrestored_placeholders.append(token)
                return token

        restored_text = RedactorConfig.PLACEHOLDER_REGEX.sub(_replace_placeholder, ai_response)

        return RestorationResult(
            restored_text=restored_text,
            restored_placeholders=restored_placeholders,
            unrestored_placeholders=unrestored_placeholders,
            is_fully_restored=len(unrestored_placeholders) == 0,
        )

    def restore(self, ai_response: str) -> str:
        """Safely restore placeholders in AI response text using this session's vault.

        Leaves unknown placeholders or placeholders from other sessions intact.
        Does NOT execute, evaluate, or interpret restored values.
        """
        return self.restore_detailed(ai_response).restored_text

    def clear(self) -> None:
        """Immediately clear all in-memory vault mappings and reset counters."""
        self._vault.clear()
        self._reverse_vault.clear()
        self._entity_counters.clear()

    @property
    def active_placeholder_count(self) -> int:
        """Number of active placeholder mappings currently retained in memory."""
        return len(self._vault)

    def contains_placeholder(self, placeholder: str) -> bool:
        """Check if placeholder is known to this session."""
        return placeholder in self._vault


class Redactor:
    """Manages redaction sessions and provides quick stateless/stateful operations."""

    def __init__(self) -> None:
        self._sessions: Dict[str, RedactionSession] = {}

    def get_or_create_session(self, session_id: Optional[str] = None) -> RedactionSession:
        """Retrieve existing session or instantiate a new isolated session."""
        sid = session_id or str(uuid.uuid4())
        if sid not in self._sessions:
            self._sessions[sid] = RedactionSession(session_id=sid)
        return self._sessions[sid]

    def clear_session(self, session_id: str) -> bool:
        """Clear and remove a session from the manager."""
        if session_id in self._sessions:
            self._sessions[session_id].clear()
            del self._sessions[session_id]
            return True
        return False

    def restore(self, session_id: str, ai_response: str) -> str:
        """Convenience method to restore text for a given session ID."""
        session = self.get_or_create_session(session_id)
        return session.restore(ai_response)

    def restore_detailed(self, session_id: str, ai_response: str) -> RestorationResult:
        """Convenience method to restore text with detailed audit for a given session ID."""
        session = self.get_or_create_session(session_id)
        return session.restore_detailed(ai_response)
