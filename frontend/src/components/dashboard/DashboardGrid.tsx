import React, { useState } from "react";
import { DragDropContext, Droppable, Draggable, DropResult } from "@hello-pangea/dnd";
import { ArrowDown, ArrowUp, GripVertical, RotateCcw } from "lucide-react";
import { RiskOverview } from "./RiskOverview";
import { EntityCounts } from "./EntityCounts";
import { ModelStatus } from "./ModelStatus";
import { BenchmarkMetrics } from "./BenchmarkMetrics";
import { ActivityLog } from "./ActivityLog";
import { Finding, RiskSummary, SystemStatus, EvaluationMetricsResponse, SafeActivityEvent } from "../../api/types";

interface DashboardGridProps {
  risk: RiskSummary | null;
  findings: Finding[] | null;
  status: SystemStatus | null;
  metrics: EvaluationMetricsResponse | null;
  activityEvents: SafeActivityEvent[];
  onClearActivityLog: () => void;
}

const DEFAULT_WIDGET_ORDER = [
  "w-risk",
  "w-counts",
  "w-status",
  "w-benchmark",
  "w-activity",
];

export const DashboardGrid: React.FC<DashboardGridProps> = ({
  risk,
  findings,
  status,
  metrics,
  activityEvents,
  onClearActivityLog,
}) => {
  const [widgetOrder, setWidgetOrder] = useState<string[]>(DEFAULT_WIDGET_ORDER);

  const handleDragEnd = (result: DropResult) => {
    if (!result.destination) return;
    const reordered = Array.from(widgetOrder);
    const [removed] = reordered.splice(result.source.index, 1);
    reordered.splice(result.destination.index, 0, removed);
    setWidgetOrder(reordered);
  };

  const moveWidget = (index: number, direction: "up" | "down") => {
    const newOrder = [...widgetOrder];
    const targetIndex = direction === "up" ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= newOrder.length) return;
    const temp = newOrder[index];
    newOrder[index] = newOrder[targetIndex];
    newOrder[targetIndex] = temp;
    setWidgetOrder(newOrder);
  };

  const handleResetLayout = () => {
    setWidgetOrder(DEFAULT_WIDGET_ORDER);
  };

  const renderWidgetContent = (id: string) => {
    switch (id) {
      case "w-risk":
        return <RiskOverview risk={risk} />;
      case "w-counts":
        return <EntityCounts findings={findings} />;
      case "w-status":
        return <ModelStatus status={status} />;
      case "w-benchmark":
        return <BenchmarkMetrics metrics={metrics} />;
      case "w-activity":
        return <ActivityLog events={activityEvents} onClearLog={onClearActivityLog} />;
      default:
        return null;
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between px-1">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Security Operations Widgets (Movable Grid)
        </h3>
        <button
          onClick={handleResetLayout}
          className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium text-slate-400 hover:text-slate-200 bg-slate-800/80 hover:bg-slate-700/80 rounded-md border border-slate-700/60 transition"
          title="Restore default widget layout"
        >
          <RotateCcw className="h-3 w-3" />
          <span>Reset Layout</span>
        </button>
      </div>

      <DragDropContext onDragEnd={handleDragEnd}>
        <Droppable droppableId="dashboard-widgets" direction="horizontal">
          {(provided) => (
            <div
              {...provided.droppableProps}
              ref={provided.innerRef}
              className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3"
            >
              {widgetOrder.map((widgetId, index) => (
                <Draggable key={widgetId} draggableId={widgetId} index={index}>
                  {(dragProvided, snapshot) => (
                    <div
                      ref={dragProvided.innerRef}
                      {...dragProvided.draggableProps}
                      className={`guardian-card min-h-[190px] flex flex-col justify-between transition-all ${
                        snapshot.isDragging ? "ring-2 ring-sky-400 shadow-2xl scale-[1.02] z-50" : ""
                      }`}
                    >
                      {/* Accessible Drag & Move Bar */}
                      <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900/80 border-b border-slate-800 rounded-t-[11px]">
                        <div
                          {...dragProvided.dragHandleProps}
                          className="flex items-center gap-1 text-slate-500 hover:text-slate-300 cursor-grab active:cursor-grabbing p-0.5"
                          title="Drag to reorder"
                          aria-label="Drag widget handle"
                        >
                          <GripVertical className="h-3.5 w-3.5" />
                          <span className="text-[10px] font-mono uppercase text-slate-500">Widget {index + 1}</span>
                        </div>

                        {/* Keyboard accessible movement buttons */}
                        <div className="flex items-center gap-0.5">
                          <button
                            onClick={() => moveWidget(index, "up")}
                            disabled={index === 0}
                            aria-label={`Move widget ${index + 1} left`}
                            className="p-1 text-slate-500 hover:text-slate-300 disabled:opacity-20 transition"
                          >
                            <ArrowUp className="h-3 w-3 -rotate-90" />
                          </button>
                          <button
                            onClick={() => moveWidget(index, "down")}
                            disabled={index === widgetOrder.length - 1}
                            aria-label={`Move widget ${index + 1} right`}
                            className="p-1 text-slate-500 hover:text-slate-300 disabled:opacity-20 transition"
                          >
                            <ArrowDown className="h-3 w-3 -rotate-90" />
                          </button>
                        </div>
                      </div>

                      {/* Widget Content */}
                      <div className="flex-1">{renderWidgetContent(widgetId)}</div>
                    </div>
                  )}
                </Draggable>
              ))}
              {provided.placeholder}
            </div>
          )}
        </Droppable>
      </DragDropContext>
    </div>
  );
};
