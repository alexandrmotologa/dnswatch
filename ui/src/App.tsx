import React, { useState, useEffect } from 'react';
import { QueryBar } from './components/QueryBar';
import { TraceTree } from './components/TraceTree';
import { PropagationMap } from './components/PropagationMap';
import { DnssecChain } from './components/DnssecChain';
import { AuditReport } from './components/AuditReport';
import { SummaryResult } from './types';
import { exportSummaryAsJSON, exportSummaryAsHTML } from './utils/export';

type Tab = 'trace' | 'propagation' | 'dnssec' | 'audit' | 'all';

export const App: React.FC = () => {
  const [domain, setDomain] = useState<string>('cloudflare.com');
  const [qtype, setQtype] = useState<string>('A');
  const [activeTab, setActiveTab] = useState<Tab>('trace');
  const [loading, setLoading] = useState<boolean>(false);
  const [summary, setSummary] = useState<SummaryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchAnalysis = async (targetDomain = domain, targetType = qtype) => {
    if (!targetDomain.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch(`/api/summary?domain=${encodeURIComponent(targetDomain)}&type=${encodeURIComponent(targetType)}`);
      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }
      const data: SummaryResult = await res.json();
      setSummary(data);
    } catch (err: any) {
      console.error('Failed to fetch summary:', err);
      setError(err.message || 'Failed to communicate with DNSWatch backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalysis('cloudflare.com', 'A');
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-sky-400 flex items-center justify-center text-lg font-bold text-white shadow-lg shadow-indigo-500/25">
              ⚡
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-white">DNSWatch</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                  v1.0.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Recursive Root Tracing, DNSSEC Validation & Global Edge Propagation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 text-xs">
            <span className="hidden md:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              Local Engine Active
            </span>

            {summary && (
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => exportSummaryAsHTML(summary)}
                  title="Download standalone styled HTML audit report"
                  className="px-2 sm:px-2.5 py-1.5 rounded-lg bg-indigo-600/90 hover:bg-indigo-600 text-white font-medium flex items-center gap-1 sm:gap-1.5 shadow-sm transition-colors cursor-pointer text-xs"
                >
                  <span>📄</span>
                  <span><span className="hidden sm:inline">Export </span>HTML</span>
                </button>
                <button
                  type="button"
                  onClick={() => exportSummaryAsJSON(summary)}
                  title="Download raw JSON report"
                  className="px-2 sm:px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-medium flex items-center gap-1 sm:gap-1.5 transition-colors cursor-pointer text-xs"
                >
                  <span>⬇</span>
                  <span>JSON</span>
                </button>
              </div>
            )}

            <a
              href="https://github.com/alexandrmotologa/dnswatch"
              target="_blank"
              rel="noopener noreferrer"
              className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors flex items-center gap-1.5 font-medium shrink-0"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
              <span className="hidden sm:inline">GitHub</span>
            </a>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 lg:px-8 py-5 sm:py-6 space-y-6">
        {/* Search & Query Bar */}
        <section className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800 shadow-xl backdrop-blur-sm">
          <QueryBar
            domain={domain}
            setDomain={setDomain}
            qtype={qtype}
            setQtype={setQtype}
            loading={loading}
            onExecute={() => fetchAnalysis(domain, qtype)}
          />
        </section>

        {/* Error notification */}
        {error && (
          <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-200 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-rose-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <span>{error}</span>
            </div>
            <button
              onClick={() => fetchAnalysis()}
              className="px-2.5 py-1 rounded bg-rose-900/60 hover:bg-rose-900 text-rose-100 font-medium transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {/* View Selection Tabs */}
        <div className="flex items-center gap-1 border-b border-slate-800/80 pb-px overflow-x-auto text-xs font-medium">
          {[
            { id: 'trace', label: 'Recursive Trace', icon: '🌳' },
            { id: 'propagation', label: 'Edge Propagation (25+ Nodes)', icon: '🌍' },
            { id: 'dnssec', label: 'DNSSEC Chain', icon: '🔒' },
            { id: 'audit', label: 'Domain Health & Audit', icon: '🛡️' },
            { id: 'all', label: 'Complete Studio View', icon: '⚡' },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as Tab)}
              className={`px-4 py-2.5 rounded-t-xl transition-all flex items-center gap-2 shrink-0 cursor-pointer ${
                activeTab === t.id
                  ? 'bg-slate-900 text-indigo-400 border-t border-x border-slate-800 font-semibold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              <span>{t.icon}</span>
              <span>{t.label}</span>
            </button>
          ))}
        </div>

        {/* Content Area */}
        <section className="space-y-8">
          {activeTab === 'trace' && (
            <TraceTree data={summary?.trace} loading={loading} />
          )}

          {activeTab === 'propagation' && (
            <PropagationMap data={summary?.propagation} loading={loading} />
          )}

          {activeTab === 'dnssec' && (
            <DnssecChain data={summary?.dnssec} loading={loading} />
          )}

          {activeTab === 'audit' && (
            <AuditReport data={summary?.audit} loading={loading} />
          )}

          {activeTab === 'all' && (
            <div className="space-y-12">
              <section className="space-y-4">
                <h2 className="text-base font-bold text-slate-200 flex items-center gap-2">
                  <span>🌳</span> 1. Recursive Delegation Trace
                </h2>
                <TraceTree data={summary?.trace} loading={loading} />
              </section>

              <section className="space-y-4">
                <h2 className="text-base font-bold text-slate-200 flex items-center gap-2">
                  <span>🌍</span> 2. Worldwide Edge Propagation
                </h2>
                <PropagationMap data={summary?.propagation} loading={loading} />
              </section>

              <section className="space-y-4">
                <h2 className="text-base font-bold text-slate-200 flex items-center gap-2">
                  <span>🔒</span> 3. DNSSEC Cryptographic Chain
                </h2>
                <DnssecChain data={summary?.dnssec} loading={loading} />
              </section>

              <section className="space-y-4">
                <h2 className="text-base font-bold text-slate-200 flex items-center gap-2">
                  <span>🛡️</span> 4. Domain Health & Hygiene Audit
                </h2>
                <AuditReport data={summary?.audit} loading={loading} />
              </section>
            </div>
          )}
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 py-6 text-center text-xs text-slate-500 font-mono">
        DNSWatch &copy; {new Date().getFullYear()} &mdash; Zero-dependency modern DNS analysis studio
      </footer>
    </div>
  );
};
