import React, { useState } from 'react';

export default function Clients({ clients = [] }) {
  const [filterRisk, setFilterRisk] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredClients = clients.filter((c) => {
    const matchesRisk = filterRisk ? c.risk_level === filterRisk : true;
    const matchesSearch = searchTerm
      ? c.hostname.toLowerCase().includes(searchTerm.toLowerCase()) || c.ip.includes(searchTerm)
      : true;
    return matchesRisk && matchesSearch;
  });

  const getDeviceIcon = (type) => {
    switch (type.toLowerCase()) {
      case 'desktop':
        return '🖥️';
      case 'laptop':
        return '💻';
      case 'mobile':
        return '📱';
      case 'iot gateway':
        return '📡';
      default:
        return '🔌';
    }
  };

  const getRiskStyle = (risk) => {
    switch (risk.toLowerCase()) {
      case 'high':
        return 'bg-rose-950 text-rose-400 border-rose-800/80';
      case 'medium':
        return 'bg-amber-950 text-amber-400 border-amber-800/80';
      default:
        return 'bg-emerald-950 text-emerald-400 border-emerald-800/60';
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Filter Header */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-white">Network Clients & Devices</h2>
            <p className="text-xs text-slate-400">
              Per-device DNS resolution volume, threat assessments, and security posture
            </p>
          </div>

          <div className="flex items-center gap-3">
            <input
              type="text"
              placeholder="Search hostname or IP..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48 font-mono"
            />
            <select
              value={filterRisk}
              onChange={(e) => setFilterRisk(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Risk Levels</option>
              <option value="High">High Risk</option>
              <option value="Medium">Medium Risk</option>
              <option value="Low">Low Risk</option>
            </select>
          </div>
        </div>
      </div>

      {/* Client Device Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filteredClients.map((client) => {
          const blockRate = client.total_queries > 0
            ? Math.round((client.blocked_queries / client.total_queries) * 100)
            : 0;

          return (
            <div
              key={client.ip}
              className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl hover:border-slate-700 transition flex flex-col justify-between"
            >
              <div>
                {/* Top Row: Icon, Name, and Status */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <span className="w-11 h-11 rounded-xl bg-slate-800 flex items-center justify-center text-xl shadow-inner">
                      {getDeviceIcon(client.device_type)}
                    </span>
                    <div>
                      <h3 className="text-sm font-bold text-white tracking-tight">{client.hostname}</h3>
                      <span className="text-xs text-cyan-400 font-mono">{client.ip}</span>
                    </div>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getRiskStyle(
                      client.risk_level
                    )}`}
                  >
                    {client.risk_level} Risk
                  </span>
                </div>

                {/* Device Type & Status */}
                <div className="flex items-center gap-2 text-xs text-slate-400 mb-4">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px]">
                    {client.device_type}
                  </span>
                  <span className="flex items-center gap-1 text-[11px] text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    {client.status}
                  </span>
                </div>

                {/* Query Metrics & Progress Bar */}
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800/80 mb-3 space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Total Queries</span>
                    <span className="text-white font-mono font-bold">{client.total_queries}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Threats Blocked</span>
                    <span className="text-rose-400 font-mono font-bold">
                      {client.blocked_queries} ({blockRate}%)
                    </span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        blockRate > 30 ? 'bg-rose-500' : blockRate > 10 ? 'bg-amber-500' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(100, Math.max(5, blockRate))}%` }}
                    ></div>
                  </div>
                </div>
              </div>

              {/* Footer */}
              <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-500 flex justify-between items-center">
                <span>Last active</span>
                <span className="font-mono text-slate-400">
                  {client.last_seen.split('T')[1]?.slice(0, 8) || 'Just now'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
