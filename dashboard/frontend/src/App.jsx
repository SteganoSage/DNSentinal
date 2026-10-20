import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Overview from './pages/Overview';
import DnsQueries from './pages/DnsQueries';
import Clients from './pages/Clients';
import SecurityAlerts from './pages/SecurityAlerts';
import Settings from './pages/Settings';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [metrics, setMetrics] = useState(null);
  const [activity, setActivity] = useState(null);
  const [queriesData, setQueriesData] = useState({ total: 0, page: 1, limit: 25, queries: [] });
  const [clients, setClients] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [settings, setSettings] = useState(null);

  // Filters for queries
  const [querySearch, setQuerySearch] = useState('');
  const [queryStatus, setQueryStatus] = useState('');
  const [queryType, setQueryType] = useState('');
  const [queryPage, setQueryPage] = useState(1);

  const API_BASE = window.location.origin;

  // Fetch all initial data
  const fetchAllData = async () => {
    try {
      const [metricsRes, activityRes, clientsRes, alertsRes, settingsRes] = await Promise.all([
        fetch(`${API_BASE}/api/metrics`).then((r) => r.json()),
        fetch(`${API_BASE}/api/activity`).then((r) => r.json()),
        fetch(`${API_BASE}/api/clients`).then((r) => r.json()),
        fetch(`${API_BASE}/api/alerts`).then((r) => r.json()),
        fetch(`${API_BASE}/api/settings`).then((r) => r.json()),
      ]);

      setMetrics(metricsRes);
      setActivity(activityRes);
      setClients(clientsRes);
      setAlerts(alertsRes);
      setSettings(settingsRes);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  };

  // Fetch queries with current filters and pagination
  const fetchQueries = async () => {
    try {
      const params = new URLSearchParams({
        page: queryPage.toString(),
        limit: '25',
      });
      if (querySearch) params.append('search', querySearch);
      if (queryStatus) params.append('status', queryStatus);
      if (queryType) params.append('qtype', queryType);

      const res = await fetch(`${API_BASE}/api/queries?${params.toString()}`);
      const data = await res.json();
      setQueriesData(data);
    } catch (err) {
      console.error('Failed to fetch queries:', err);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  useEffect(() => {
    fetchQueries();
  }, [querySearch, queryStatus, queryType, queryPage]);

  // Simulate a query
  const handleSimulateQuery = async (domain) => {
    try {
      await fetch(`${API_BASE}/api/queries/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ qname: domain }),
      });
      // Refresh both queries and metrics
      await Promise.all([fetchQueries(), fetchAllData()]);
    } catch (err) {
      console.error('Failed to simulate query:', err);
    }
  };

  // Dismiss an alert
  const handleDismissAlert = async (id) => {
    try {
      await fetch(`${API_BASE}/api/alerts/${id}/dismiss`, { method: 'POST' });
      await fetchAllData();
    } catch (err) {
      console.error('Failed to dismiss alert:', err);
    }
  };

  // Toggle mitigate alert
  const handleToggleMitigate = async (id) => {
    try {
      await fetch(`${API_BASE}/api/alerts/${id}/toggle-mitigate`, { method: 'POST' });
      await fetchAllData();
    } catch (err) {
      console.error('Failed to toggle alert status:', err);
    }
  };

  // Save settings
  const handleSaveSettings = async (newSettings) => {
    try {
      const res = await fetch(`${API_BASE}/api/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newSettings),
      });
      const data = await res.json();
      setSettings(data);
    } catch (err) {
      console.error('Failed to save settings:', err);
    }
  };

  // Reset demo dataset
  const handleResetDemoData = async () => {
    try {
      await fetch(`${API_BASE}/api/settings/reset-demo-data`, { method: 'POST' });
      await Promise.all([fetchAllData(), fetchQueries()]);
    } catch (err) {
      console.error('Failed to reset demo dataset:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans antialiased selection:bg-cyan-500 selection:text-white">
      {/* Header with Navigation and Sample Data Disclaimer */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        activeAlertsCount={metrics?.active_alerts_count || 0}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <Overview
            metrics={metrics}
            activity={activity}
            recentQueries={queriesData.queries}
            onNavigate={(tab) => setActiveTab(tab)}
            onSimulateQuery={handleSimulateQuery}
          />
        )}

        {activeTab === 'queries' && (
          <DnsQueries
            queries={queriesData.queries}
            total={queriesData.total}
            page={queryPage}
            limit={queriesData.limit}
            onPageChange={(p) => setQueryPage(p)}
            onSearchChange={(s) => {
              setQuerySearch(s);
              setQueryPage(1);
            }}
            statusFilter={queryStatus}
            onStatusFilterChange={(st) => {
              setQueryStatus(st);
              setQueryPage(1);
            }}
            qtypeFilter={queryType}
            onQtypeFilterChange={(qt) => {
              setQueryType(qt);
              setQueryPage(1);
            }}
            onSimulateQuery={handleSimulateQuery}
          />
        )}

        {activeTab === 'clients' && <Clients clients={clients} />}

        {activeTab === 'alerts' && (
          <SecurityAlerts
            alerts={alerts}
            onDismiss={handleDismissAlert}
            onToggleMitigate={handleToggleMitigate}
          />
        )}

        {activeTab === 'settings' && (
          <Settings
            settings={settings}
            onSaveSettings={handleSaveSettings}
            onResetDemoData={handleResetDemoData}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="bg-slate-900 border-t border-slate-800/80 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>DNSentinel — Secure Recursive DNS Resolver Dashboard</span>
          <span className="font-mono text-[11px] text-slate-400">
            C++20 Gateway Core • FastAPI Backend • React Frontend • SQLite Demo Mode
          </span>
        </div>
      </footer>
    </div>
  );
}
