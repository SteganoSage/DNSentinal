import React, { useState } from 'react';

export default function Settings({ settings, onSaveSettings, onResetDemoData }) {
  const [formData, setFormData] = useState(settings || {
    ml_dga_threshold: 0.75,
    tunnel_entropy_threshold: 4.5,
    rate_limit_rps: 100,
    cache_ttl_seconds: 300,
    enable_cname_inspection: true,
    enable_0x20_encoding: true,
    log_retention_days: 7,
    demo_mode: true
  });
  const [saveStatus, setSaveStatus] = useState('');
  const [isResetting, setIsResetting] = useState(false);

  const handleChange = (field, val) => {
    setFormData((prev) => ({ ...prev, [field]: val }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaveStatus('Saving demo settings...');
    await onSaveSettings(formData);
    setSaveStatus('Settings updated successfully in SQLite demo database!');
    setTimeout(() => setSaveStatus(''), 4000);
  };

  const handleReset = async () => {
    if (window.confirm('Reset all demo queries, clients, and alerts back to default sample state?')) {
      setIsResetting(true);
      await onResetDemoData();
      setIsResetting(false);
      alert('Demo sample dataset reset successfully.');
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Safety Sandbox Callout */}
      <div className="bg-emerald-950/40 border border-emerald-800/80 rounded-2xl p-4 flex items-start gap-3 shadow-lg">
        <span className="text-2xl">🔒</span>
        <div>
          <h3 className="text-sm font-bold text-emerald-300">Safety Sandbox Active</h3>
          <p className="text-xs text-emerald-200/90 mt-0.5 leading-relaxed">
            All controls on this page modify the local demonstration SQLite database only. The core C++ resolver
            configuration (<code className="bg-emerald-950 px-1 py-0.5 rounded text-white font-mono text-[11px]">config/dnsentinel.yaml</code>)
            is strictly protected and will not be touched or altered.
          </p>
        </div>
      </div>

      {/* Main Settings Card */}
      <form onSubmit={handleSave} className="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl space-y-6">
        <div>
          <h2 className="text-xl font-bold text-white">Dashboard Policy & ML Controls</h2>
          <p className="text-xs text-slate-400">
            Tune algorithmic detection thresholds, caching behavior, and rate limiting rules for evaluation
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-slate-800">
          {/* ML DGA Threshold */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-slate-200">DGA Classifier Cutoff</label>
              <span className="text-cyan-400 font-mono font-bold text-xs">{formData.ml_dga_threshold}</span>
            </div>
            <input
              type="range"
              min="0.50"
              max="0.95"
              step="0.05"
              value={formData.ml_dga_threshold}
              onChange={(e) => handleChange('ml_dga_threshold', parseFloat(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Confidence threshold for blocking algorithmically generated domain names.
            </p>
          </div>

          {/* DNS Tunnel Entropy Threshold */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-slate-200">Tunnel Shannon Entropy</label>
              <span className="text-cyan-400 font-mono font-bold text-xs">
                {formData.tunnel_entropy_threshold} bits
              </span>
            </div>
            <input
              type="range"
              min="3.0"
              max="6.5"
              step="0.1"
              value={formData.tunnel_entropy_threshold}
              onChange={(e) => handleChange('tunnel_entropy_threshold', parseFloat(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Flags subdomains with high character randomness indicative of encoded binary data.
            </p>
          </div>

          {/* Rate Limiting */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-slate-200">Client Rate Limit</label>
              <span className="text-emerald-400 font-mono font-bold text-xs">
                {formData.rate_limit_rps} req/sec
              </span>
            </div>
            <input
              type="range"
              min="20"
              max="500"
              step="10"
              value={formData.rate_limit_rps}
              onChange={(e) => handleChange('rate_limit_rps', parseInt(e.target.value))}
              className="w-full accent-emerald-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Maximum queries per second permitted before applying response rate limiting (RRL).
            </p>
          </div>

          {/* Cache TTL */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-slate-200">Negative Cache TTL</label>
              <span className="text-emerald-400 font-mono font-bold text-xs">
                {formData.cache_ttl_seconds} s
              </span>
            </div>
            <input
              type="range"
              min="30"
              max="1800"
              step="30"
              value={formData.cache_ttl_seconds}
              onChange={(e) => handleChange('cache_ttl_seconds', parseInt(e.target.value))}
              className="w-full accent-emerald-500 cursor-pointer"
            />
            <p className="text-[11px] text-slate-500">
              Duration to store NXDOMAIN and failure responses to protect upstream root servers.
            </p>
          </div>
        </div>

        {/* Feature Toggles */}
        <div className="pt-4 border-t border-slate-800 space-y-3">
          <h3 className="text-sm font-semibold text-white">Active Defense Modules</h3>

          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800">
            <div>
              <span className="text-xs font-semibold text-white block">CNAME-Cloaking Deep Inspection</span>
              <span className="text-[11px] text-slate-400">
                Chases canonical aliases to block disguised ad-trackers before returning answers.
              </span>
            </div>
            <input
              type="checkbox"
              checked={formData.enable_cname_inspection}
              onChange={(e) => handleChange('enable_cname_inspection', e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
            />
          </div>

          <div className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800">
            <div>
              <span className="text-xs font-semibold text-white block">0x20 Bit-Case Anti-Poisoning Randomization</span>
              <span className="text-[11px] text-slate-400">
                Randomizes capitalization in upstream query names (e.g. gOoGLe.cOM) to thwart off-path spoofers.
              </span>
            </div>
            <input
              type="checkbox"
              checked={formData.enable_0x20_encoding}
              onChange={(e) => handleChange('enable_0x20_encoding', e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
            />
          </div>
        </div>

        {/* Action Row */}
        <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="text-xs font-medium text-emerald-400">{saveStatus}</div>
          <div className="flex items-center gap-3 w-full sm:w-auto">
            <button
              type="button"
              onClick={handleReset}
              disabled={isResetting}
              className="flex-1 sm:flex-initial px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition"
            >
              {isResetting ? 'Resetting...' : 'Reset Demo Dataset'}
            </button>
            <button
              type="submit"
              className="flex-1 sm:flex-initial px-5 py-2 bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white text-xs font-semibold rounded-lg shadow-lg shadow-cyan-950/50 transition"
            >
              Save Demo Settings
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
