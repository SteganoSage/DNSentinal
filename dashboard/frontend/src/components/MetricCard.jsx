import React from 'react';

export default function MetricCard({ title, value, subtext, icon, trend, color = 'cyan' }) {
  const colorStyles = {
    cyan: 'border-cyan-500/30 bg-cyan-950/20 text-cyan-400',
    rose: 'border-rose-500/30 bg-rose-950/20 text-rose-400',
    emerald: 'border-emerald-500/30 bg-emerald-950/20 text-emerald-400',
    amber: 'border-amber-500/30 bg-amber-950/20 text-amber-400',
    purple: 'border-purple-500/30 bg-purple-950/20 text-purple-400',
  };

  return (
    <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl hover:border-slate-700 transition duration-200">
      <div className="flex items-center justify-between mb-3">
        <span className="text-sm font-medium text-slate-400">{title}</span>
        <div className={`w-10 h-10 rounded-xl border flex items-center justify-center text-lg ${colorStyles[color]}`}>
          {icon}
        </div>
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-3xl font-black tracking-tight text-white">{value}</span>
        {trend && (
          <span className={`text-xs font-semibold ${trend.positive ? 'text-emerald-400' : 'text-rose-400'}`}>
            {trend.value}
          </span>
        )}
      </div>
      {subtext && <p className="mt-2 text-xs text-slate-500">{subtext}</p>}
    </div>
  );
}
