import React, { useState } from 'react';

export default function DnsQueries({
  queries,
  total,
  page,
  limit,
  onPageChange,
  onSearchChange,
  statusFilter,
  onStatusFilterChange,
  qtypeFilter,
  onQtypeFilterChange,
  onSimulateQuery,
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [simDomain, setSimDomain] = useState('');
  const [selectedQuery, setSelectedQuery] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    onSearchChange(searchTerm);
  };

  const handleSimulate = async (e) => {
    e.preventDefault();
    if (!simDomain.trim()) return;
    setIsSimulating(true);
    await onSimulateQuery(simDomain.trim());
    setSimDomain('');
    setIsSimulating(false);
  };

  const totalPages = Math.ceil(total / limit) || 1;

  return (
    <div className="space-y-6">
      {/* Page Title & Simulator Box */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-xl font-bold text-white">DNS Queries Log</h2>
            <p className="text-xs text-slate-400">
              Inspect recursive resolutions, cache hits, latency, and firewall block decisions
            </p>
          </div>

          {/* Interactive Simulation Form */}
          <form onSubmit={handleSimulate} className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Test domain (e.g. evil-dga.biz)..."
              value={simDomain}
              onChange={(e) => setSimDomain(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-56 font-mono"
            />
            <button
              type="submit"
              disabled={isSimulating}
              className="px-3 py-1.5 bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white text-xs font-semibold rounded-lg shadow transition disabled:opacity-50 whitespace-nowrap"
            >
              {isSimulating ? 'Testing...' : '⚡ Test Query'}
            </button>
          </form>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col sm:flex-row gap-3 pt-4 border-t border-slate-800">
          <form onSubmit={handleSearchSubmit} className="flex-1 flex gap-2">
            <input
              type="text"
              placeholder="Search domain or client (e.g. github, 192.168.1.10)..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
            >
              Search
            </button>
          </form>

          <div className="flex gap-2">
            <select
              value={statusFilter}
              onChange={(e) => onStatusFilterChange(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Statuses</option>
              <option value="ALLOW">Allowed</option>
              <option value="BLOCK">Blocked</option>
            </select>

            <select
              value={qtypeFilter}
              onChange={(e) => onQtypeFilterChange(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Types</option>
              <option value="A">A (IPv4)</option>
              <option value="AAAA">AAAA (IPv6)</option>
              <option value="TXT">TXT</option>
              <option value="CNAME">CNAME</option>
            </select>
          </div>
        </div>
      </div>

      {/* Query Log Table */}
      <div className="bg-slate-900/90 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Client</th>
                <th className="py-3 px-4">Domain (QNAME)</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">RCode</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4">Latency</th>
                <th className="py-3 px-4">Cache</th>
                <th className="py-3 px-4">Decision</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {queries.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-8 text-center text-slate-500 font-sans">
                    No DNS queries found matching your filters.
                  </td>
                </tr>
              ) : (
                queries.map((q) => (
                  <tr
                    key={q.id}
                    onClick={() => setSelectedQuery(q)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                      {q.timestamp.split('T')[1]?.slice(0, 8) || q.timestamp}
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      <span className="text-white font-sans font-medium block">{q.client_name}</span>
                      <span className="text-[10px] text-slate-500">{q.client_ip}</span>
                    </td>
                    <td className="py-3 px-4 text-cyan-300 font-semibold max-w-[240px] truncate">
                      {q.qname}
                      {q.block_reason && (
                        <span className="block text-[10px] text-rose-400 font-sans truncate font-normal">
                          {q.block_reason}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-300">{q.qtype}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`text-[11px] font-bold ${
                          q.rcode === 'NOERROR'
                            ? 'text-emerald-400'
                            : q.rcode === 'NXDOMAIN'
                            ? 'text-amber-400'
                            : 'text-rose-400'
                        }`}
                      >
                        {q.rcode}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                        {q.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300">{q.latency_ms} ms</td>
                    <td className="py-3 px-4">
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
                    <td className="py-3 px-4">
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
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="bg-slate-950/60 px-4 py-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <span>
            Showing page <span className="text-white font-semibold">{page}</span> of{' '}
            <span className="text-white font-semibold">{totalPages}</span> ({total} total queries)
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 transition"
            >
              Previous
            </button>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 disabled:opacity-40 transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Query Detail Modal */}
      {selectedQuery && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-xl">🔍</span>
                <h3 className="text-base font-bold text-white">DNS Query Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedQuery(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 block">Requested Domain (QNAME)</span>
                <span className="text-cyan-400 font-mono font-bold text-sm break-all">
                  {selectedQuery.qname}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">Client Hostname</span>
                  <span className="text-white font-sans">{selectedQuery.client_name}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Client IP</span>
                  <span className="text-white">{selectedQuery.client_ip}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Record Type</span>
                  <span className="text-white">{selectedQuery.qtype}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Transport Protocol</span>
                  <span className="text-white">{selectedQuery.protocol}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Response Code</span>
                  <span className="text-white">{selectedQuery.rcode}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Resolution Latency</span>
                  <span className="text-white">{selectedQuery.latency_ms} ms</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Cache Engine</span>
                  <span className="text-white">{selectedQuery.cache_status}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Policy Action</span>
                  <span className="text-white font-bold">{selectedQuery.policy_action}</span>
                </div>
              </div>

              {selectedQuery.block_reason && (
                <div className="bg-rose-950/40 border border-rose-800/80 rounded-xl p-3">
                  <span className="text-rose-400 font-bold block mb-1">Defense Interception Reason</span>
                  <p className="text-rose-200 text-xs">{selectedQuery.block_reason}</p>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedQuery(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
