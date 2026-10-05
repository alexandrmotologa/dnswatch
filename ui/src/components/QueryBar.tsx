import React from 'react';

interface QueryBarProps {
  domain: string;
  setDomain: (d: string) => void;
  qtype: string;
  setQtype: (t: string) => void;
  loading: boolean;
  onExecute: () => void;
}

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'PTR'];

export const QueryBar: React.FC<QueryBarProps> = ({
  domain,
  setDomain,
  qtype,
  setQtype,
  loading,
  onExecute,
}) => {
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (domain.trim()) {
      onExecute();
    }
  };

  const handlePreset = (preset: string) => {
    setDomain(preset);
  };

  return (
    <div className="w-full space-y-3">
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-2.5">
        <div className="relative flex-1">
          <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter domain (e.g. cloudflare.com)..."
            className="w-full pl-10 pr-4 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 font-mono text-sm transition-all shadow-inner"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <select
            value={qtype}
            onChange={(e) => setQtype(e.target.value)}
            className="w-28 sm:w-auto px-3.5 py-2.5 bg-slate-900/80 border border-slate-700/80 rounded-xl text-indigo-300 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 cursor-pointer shadow-inner shrink-0"
          >
            {RECORD_TYPES.map((t) => (
              <option key={t} value={t} className="bg-slate-900 text-slate-200">
                {t}
              </option>
            ))}
          </select>

          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="flex-1 sm:flex-none justify-center px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white font-medium text-sm rounded-xl transition-all shadow-lg shadow-indigo-600/25 flex items-center gap-2 cursor-pointer disabled:cursor-not-allowed shrink-0"
          >
            {loading ? (
              <>
                <svg className="animate-spin w-4 h-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <span>Run Analysis</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Quick Presets */}
      <div className="flex items-center gap-2 text-xs text-slate-400 overflow-x-auto pb-1">
        <span className="text-slate-500 shrink-0 font-medium">Quick Presets:</span>
        {[
          { label: 'cloudflare.com (DNSSEC)', domain: 'cloudflare.com' },
          { label: 'google.com (Anycast)', domain: 'google.com' },
          { label: 'dnssec-failed.org (Bogus)', domain: 'dnssec-failed.org' },
          { label: 'github.com (Apex)', domain: 'github.com' },
        ].map((p) => (
          <button
            key={p.domain}
            type="button"
            onClick={() => handlePreset(p.domain)}
            className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 hover:text-slate-200 border border-slate-700/50 transition-colors shrink-0 font-mono text-[11px]"
          >
            {p.label}
          </button>
        ))}
      </div>
    </div>
  );
};
