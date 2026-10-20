import React from 'react';
import MetricCard from '../components/MetricCard';
import QueryChart from '../components/QueryChart';

export default function Overview({ metrics, activity, recentQueries, onNavigate, onSimulateQuery }) {
  if (!metrics) {
    return (
      <div className="flex items-center justify-center p-12 text-slate-400">
        Loading DNSentinel metrics...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Threat Alert Banner if Active Threats Exist */}
      {metrics.active_alerts_count > 0 && (
        <div className="bg-gradient-to-r from-rose-950/60 to-slate-900 border border-rose-800/80 rounded-2xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-lg shadow-rose-950/20">
          <div className="flex items-center gap-3">
            <span className="w-10 h-10 rounded-xl bg-rose-600/20 border border-rose-500/40 flex items-center justify-center text-rose-400 text-xl">
              ⚠️
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-rose-300">
                  {metrics.active_alerts_count} Active Security Threats Detected
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 bg-rose-900/60 text-rose-300 rounded border border-rose-700">
                  Requires Attention
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                DNSentinel ML and policy engines flagged DGA botnet domains and high-entropy DNS tunneling channels.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigate('alerts')}
            className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-lg shadow transition flex items-center gap-1.5 whitespace-nowrap"
          >
            Investigate Threats →
          </button>
        </div>
      )}

      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total DNS Queries"
          value={metrics.total_queries.toLocaleString()}
          subtext={`${metrics.allowed_queries} allowed • ${metrics.blocked_queries} blocked`}
          icon="🌐"
          color="cyan"
        />
        <MetricCard
          title="Blocked Queries"
          value={metrics.blocked_queries.toLocaleString()}
          subtext={`${metrics.block_rate_percent}% total block rate`}
          icon="🛡️"
          color="rose"
          trend={{ value: `${metrics.block_rate_percent}% filtered`, positive: false }}
        />
        <MetricCard
          title="Cache Hit Ratio"
          value={`${(metrics.cache_hit_ratio * 100).toFixed(1)}%`}
          subtext={`${metrics.cache_hits} hits • ${metrics.cache_misses} misses`}
          icon="⚡"
          color="emerald"
          trend={{ value: 'Ultra-fast resolution', positive: true }}
        />
        <MetricCard
          title="Average Latency"
          value={`${metrics.avg_latency_ms} ms`}
          subtext="Fast-path in-memory resolver"
          icon="⏱️"
          color="purple"
        />
      </div>

      {/* Main Charts & Threat Categories Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Timeline Chart */}
        <div className="lg:col-span-2 bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl">
          <QueryChart points={activity?.points || []} />
        </div>

        {/* Threat Categories Breakdown */}
        <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl flex flex-col justify-between">
          <div>
            <h3 className="text-base font-semibold text-white mb-1">Defense Interceptions</h3>
            <p className="text-xs text-slate-400 mb-4">Sample attack mitigation breakdown</p>

            <div className="space-y-3.5">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">DGA Malware Domains</span>
                  <span className="text-rose-400 font-mono font-semibold">41%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-rose-500 rounded-full" style={{ width: '41%' }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">Covert DNS Tunnels</span>
                  <span className="text-amber-400 font-mono font-semibold">28%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-amber-500 rounded-full" style={{ width: '28%' }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">CNAME Cloaking Trackers</span>
                  <span className="text-purple-400 font-mono font-semibold">19%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-purple-500 rounded-full" style={{ width: '19%' }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-300 font-medium">DNS Rebinding Exploits</span>
                  <span className="text-cyan-400 font-mono font-semibold">12%</span>
                </div>
                <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-cyan-500 rounded-full" style={{ width: '12%' }}></div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800 text-xs text-slate-400 flex items-center justify-between">
            <span>Resolver Engine:</span>
            <span className="text-emerald-400 font-medium flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span> Active (Iterative Mode)
            </span>
          </div>
        </div>
      </div>

      {/* Recent Queries Preview Table */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-semibold text-white">Recent DNS Queries Stream</h3>
            <p className="text-xs text-slate-400">Real-time inspection of client requests</p>
          </div>
          <button
            onClick={() => onNavigate('queries')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
          >
            View Full Query Log ({metrics.total_queries}) →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Client</th>
                <th className="py-2.5 px-3">Domain (QNAME)</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3">Cache</th>
                <th className="py-2.5 px-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {(recentQueries || []).slice(0, 6).map((q) => (
                <tr key={q.id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {q.timestamp.split('T')[1]?.slice(0, 8) || q.timestamp}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    <span className="text-white font-sans">{q.client_name}</span>
                    <span className="block text-[10px] text-slate-500">{q.client_ip}</span>
                  </td>
                  <td className="py-2.5 px-3 text-cyan-300 font-semibold max-w-[200px] truncate">
                    {q.qname}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{q.qtype}</td>
                  <td className="py-2.5 px-3 text-slate-300">{q.latency_ms} ms</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        q.cache_status === 'HIT'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {q.cache_status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        q.policy_action === 'BLOCK'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800/60'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                      }`}
                    >
                      {q.policy_action}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
