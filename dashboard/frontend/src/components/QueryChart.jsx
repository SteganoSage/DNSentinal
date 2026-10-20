import React from 'react';

export default function QueryChart({ points = [] }) {
  if (!points || points.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-slate-500 text-sm">
        No activity points available to chart.
      </div>
    );
  }

  // Calculate coordinates for SVG line rendering
  const maxVal = Math.max(...points.map((p) => p.total), 10);
  const width = 600;
  const height = 180;
  const padding = 20;

  const getX = (index) => padding + (index / (points.length - 1 || 1)) * (width - padding * 2);
  const getY = (val) => height - padding - (val / maxVal) * (height - padding * 2);

  const totalPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(p.total)}`).join(' ');
  const allowedPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(p.allowed)}`).join(' ');
  const blockedPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(p.blocked)}`).join(' ');

  const areaTotalPath = `${totalPath} L ${getX(points.length - 1)} ${height - padding} L ${getX(0)} ${height - padding} Z`;

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-base font-semibold text-white">DNS Query Activity Timeline</h3>
          <p className="text-xs text-slate-400">Past query volume, allowed lookups, and blocked threats</p>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-cyan-500"></span>
            <span className="text-slate-300">Total</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
            <span className="text-slate-300">Allowed</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500"></span>
            <span className="text-slate-300">Blocked</span>
          </div>
        </div>
      </div>

      <div className="relative bg-slate-950/60 rounded-xl p-3 border border-slate-800/80">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-48 overflow-visible">
          {/* Subtle grid lines */}
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#334155" strokeDasharray="3 3" opacity="0.4" />
          <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="#334155" strokeDasharray="3 3" opacity="0.4" />
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#334155" opacity="0.6" />

          {/* Area fill */}
          <path d={areaTotalPath} fill="url(#cyanGradient)" opacity="0.25" />

          <defs>
            <linearGradient id="cyanGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Lines */}
          <path d={totalPath} fill="none" stroke="#06b6d4" strokeWidth="2.5" strokeLinecap="round" />
          <path d={allowedPath} fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" />
          <path d={blockedPath} fill="none" stroke="#f43f5e" strokeWidth="2" strokeLinecap="round" />

          {/* Data Points */}
          {points.map((p, i) => (
            <g key={i}>
              <circle cx={getX(i)} cy={getY(p.total)} r="3" fill="#06b6d4" />
              <circle cx={getX(i)} cy={getY(p.blocked)} r="3" fill="#f43f5e" />
            </g>
          ))}
        </svg>

        {/* X Axis Time Labels */}
        <div className="flex justify-between px-4 mt-2 text-[10px] text-slate-500 font-mono">
          {points.map((p, i) => (
            <span key={i}>{p.time_label}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
