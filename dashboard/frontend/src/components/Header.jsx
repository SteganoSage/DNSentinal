import React from 'react';

export default function Header({ activeTab, setActiveTab, activeAlertsCount }) {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: 'Activity' },
    { id: 'queries', label: 'DNS Queries', icon: 'ListFilter' },
    { id: 'clients', label: 'Clients', icon: 'Devices' },
    { id: 'alerts', label: 'Security Alerts', icon: 'ShieldAlert', badge: activeAlertsCount },
    { id: 'settings', label: 'Settings', icon: 'Sliders' },
  ];

  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-50">
      {/* Sample Data Disclaimer Bar */}
      <div className="bg-amber-950/70 border-b border-amber-800/60 px-4 py-1.5 text-xs text-amber-300 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span>
          <span className="font-semibold tracking-wide uppercase text-[11px] bg-amber-900/80 px-2 py-0.5 rounded border border-amber-700">
            Demo / Sample Data
          </span>
          <span className="text-amber-200/90 hidden sm:inline">
            This dashboard displays simulated network traffic and threat models for evaluation. Core resolver config is isolated.
          </span>
        </div>
        <span className="text-[11px] text-amber-400 font-mono">SQLite Mode • Read/Write Demo Sandbox</span>
      </div>

      {/* Main Navbar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Project Title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-emerald-500 flex items-center justify-center shadow-lg shadow-cyan-950/50">
              <span className="text-white font-black text-xl">🛡️</span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-lg text-white tracking-tight">DNSentinel</span>
                <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded">
                  Gateway SOC
                </span>
              </div>
              <p className="text-xs text-slate-400">Secure Recursive DNS Resolver & Threat Monitor</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex space-x-1 sm:space-x-2">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`relative px-3 sm:px-4 py-2 rounded-lg text-sm font-medium transition-all duration-150 flex items-center gap-2 ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 text-xs font-bold rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>
    </header>
  );
}
