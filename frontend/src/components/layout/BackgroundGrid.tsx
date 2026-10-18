import React from "react";

export const BackgroundGrid: React.FC = () => {
  return (
    <div
      className="fixed inset-0 pointer-events-none z-0 overflow-hidden"
      aria-hidden="true"
    >
      {/* Circuit Grid */}
      <div className="absolute inset-0 bg-circuit-grid opacity-30" />

      {/* Radial Gradient Ambient Glows (Inspired by block-hero.tsx) */}
      <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-gradient-to-tr from-sky-500/15 via-violet-600/15 to-transparent rounded-full blur-3xl" />
      <div className="absolute top-1/3 -left-32 w-[450px] h-[450px] bg-gradient-to-br from-indigo-600/10 to-transparent rounded-full blur-3xl" />
      <div className="absolute bottom-10 right-0 w-[500px] h-[500px] bg-gradient-to-tl from-sky-600/10 to-transparent rounded-full blur-3xl" />
    </div>
  );
};
