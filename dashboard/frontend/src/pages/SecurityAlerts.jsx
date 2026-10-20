import React, { useState } from 'react';

export default function SecurityAlerts({ alerts = [], onDismiss, onToggleMitigate }) {
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterThreat, setFilterThreat] = useState('');

  const filteredAlerts = alerts.filter((a) => {
    const matchesSev = filterSeverity ? a.severity === filterSeverity : true;
    const matchesThreat = filterThreat ? a.threat_type === filterThreat : true;
    return matchesSev && matchesThreat;
  });

  const getSeverityBadge = (sev) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950 text-rose-300 border-rose-700';
      case 'high':
        return 'bg-orange-950 text-orange-300 border-orange-700';
      case 'medium':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      default:
        return 'bg-blue-950 text-blue-300 border-blue-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white">Security Threat Intelligence</h2>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
                AI / Policy Defense
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Deep forensic explanations for algorithmically generated domains, DNS tunnels, and cache attacks
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
            </select>

            <select
              value={filterThreat}
              onChange={(e) => setFilterThreat(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Threat Types</option>
              <option value="DGA Malware Domain">DGA Malware Domain</option>
              <option value="DNS Data Exfiltration Tunnel">DNS Data Exfiltration Tunnel</option>
              <option value="CNAME Cloaking Tracker">CNAME Cloaking Tracker</option>
              <option value="DNS Rebinding Attack">DNS Rebinding Attack</option>
              <option value="Off-Path Cache Poisoning Attempt">Off-Path Cache Poisoning Attempt</option>
            </select>
          </div>
        </div>
      </div>

      {/* Security Alerts List */}
      <div className="space-y-4">
        {filteredAlerts.length === 0 ? (
          <div className="bg-slate-900/80 rounded-2xl border border-slate-800 p-12 text-center text-slate-500">
            No security threat alerts found matching the selected filters.
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={`bg-slate-900/90 rounded-2xl border p-5 shadow-xl transition ${
                alert.status === 'Active'
                  ? 'border-rose-800/80 hover:border-rose-700 shadow-rose-950/10'
                  : 'border-slate-800 opacity-75'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                {/* Threat Details */}
                <div className="space-y-3 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2.5 py-0.5 rounded-md text-[11px] font-bold border uppercase tracking-wider ${getSeverityBadge(
                        alert.severity
                      )}`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-white font-bold text-base">{alert.threat_type}</span>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${
                        alert.status === 'Active'
                          ? 'bg-rose-950/70 text-rose-300 border-rose-800'
                          : 'bg-emerald-950/70 text-emerald-300 border-emerald-800'
                      }`}
                    >
                      {alert.status}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">
                      Logged {alert.timestamp.split('T')[1]?.slice(0, 8) || alert.timestamp}
                    </span>
                  </div>

                  {/* Suspicious Domain Banner */}
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500 text-xs font-semibold">Flagged Domain:</span>
                      <span className="text-cyan-400 font-mono font-bold text-sm tracking-wide">
                        {alert.domain}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-slate-400">
                        Client: <span className="text-white font-mono">{alert.client_ip}</span>
                      </span>
                      <span className="text-slate-400">
                        ML Risk Score:{' '}
                        <span className="text-rose-400 font-mono font-bold">
                          {(alert.risk_score * 100).toFixed(0)}%
                        </span>
                      </span>
                    </div>
                  </div>

                  {/* High-level Description */}
                  <p className="text-xs text-slate-300 leading-relaxed">{alert.description}</p>

                  {/* Forensic Evidence: "Why Was This Flagged?" */}
                  <div className="bg-slate-950/90 rounded-xl border border-slate-800/80 p-3.5 space-y-2">
                    <div className="flex items-center gap-1.5 text-xs font-bold text-amber-400">
                      <span>🔬</span>
                      <span>Forensic Evidence & Detection Breakdown ("Why Flagged?"):</span>
                    </div>
                    <ul className="space-y-1.5 text-xs text-slate-300 pl-2">
                      {alert.detection_evidence.map((evidence, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-cyan-400 text-sm leading-none">•</span>
                          <span>{evidence}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Right Action Column */}
                <div className="flex lg:flex-col items-center lg:items-end justify-between gap-2 pt-2 lg:pt-0 border-t lg:border-t-0 border-slate-800">
                  <div className="text-right hidden lg:block">
                    <span className="text-[10px] text-slate-500 block">Enforcement Action</span>
                    <span className="text-xs font-bold text-emerald-400 font-mono">
                      {alert.action_taken}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onToggleMitigate(alert.id)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                        alert.status === 'Active'
                          ? 'bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 border border-emerald-700'
                          : 'bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-700'
                      }`}
                    >
                      {alert.status === 'Active' ? 'Mark Mitigated' : 'Reactivate'}
                    </button>
                    <button
                      onClick={() => onDismiss(alert.id)}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
