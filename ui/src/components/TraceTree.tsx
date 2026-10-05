import React from 'react';
import { TraceResult } from '../types';

interface TraceTreeProps {
  data?: TraceResult;
  loading: boolean;
}

export const TraceTree: React.FC<TraceTreeProps> = ({ data, loading }) => {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-slate-400 space-y-3">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm">Walking recursive delegation tree from IANA root hints...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-8 text-center text-slate-500 text-sm">
        No trace data available. Enter a domain and run analysis.
      </div>
    );
  }

  // Format RTT in ms
  const formatRTT = (nanos: number) => {
    const ms = nanos / 1000000;
    let color = 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60';
    if (ms >= 120) {
      color = 'text-rose-400 bg-rose-950/60 border-rose-800/60';
    } else if (ms >= 40) {
      color = 'text-amber-400 bg-amber-950/60 border-amber-800/60';
    }
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-xs font-mono font-medium border ${color}`}>
        {ms.toFixed(1)}ms
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Overview header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/60 border border-slate-800 shadow-md">
        <div>
          <h3 className="text-base font-semibold text-slate-200">
            Recursive Delegation Trace
          </h3>
          <p className="text-xs text-slate-400 font-mono">
            {data.domain} (Type: {data.query_type})
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs font-mono">
          <div>
            <span className="text-slate-500">Total Latency:</span>{' '}
            <span className="text-indigo-400 font-medium">{(data.total_rtt / 1000000).toFixed(1)}ms</span>
          </div>
          <div>
            <span className="text-slate-500">Hops:</span>{' '}
            <span className="text-slate-300 font-medium">{data.hops.length}</span>
          </div>
          <div>
            <span className="text-slate-500">Status:</span>{' '}
            {data.success ? (
              <span className="text-emerald-400 font-medium">✔ Resolved</span>
            ) : (
              <span className="text-rose-400 font-medium">✖ {data.error || 'Failed'}</span>
            )}
          </div>
        </div>
      </div>

      {/* CNAME chain if any */}
      {data.cname_chain && data.cname_chain.length > 0 && (
        <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-800/40 text-xs">
          <div className="font-semibold text-indigo-300 mb-1 flex items-center gap-1.5">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
            CNAME Redirection Chain:
          </div>
          <div className="font-mono text-slate-300 space-y-0.5">
            {data.cname_chain.map((c, idx) => (
              <div key={idx} className="pl-4 break-all">↳ {c}</div>
            ))}
          </div>
        </div>
      )}

      {/* Hops tree list */}
      <div className="relative pl-6 sm:pl-7 space-y-5 sm:space-y-6 before:absolute before:left-2 before:top-4 before:bottom-4 before:w-0.5 before:bg-gradient-to-b before:from-indigo-500 before:via-sky-500 before:to-emerald-500">
        {(data.hops || []).map((hop) => (
          <div key={hop.step} className="relative group">
            {/* Step marker */}
            <div className="absolute -left-[24px] sm:-left-[27px] top-3.5 w-5 h-5 rounded-full bg-slate-900 border-2 border-indigo-500 flex items-center justify-center text-[10px] font-bold text-indigo-300 shadow-md">
              {hop.step}
            </div>

            <div className="p-3.5 sm:p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors shadow-lg">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs px-2 py-0.5 rounded font-mono font-semibold bg-indigo-950/80 text-indigo-300 border border-indigo-800/50">
                    Zone: {hop.zone}
                  </span>
                  <span className="text-sm font-medium text-slate-100 break-all">
                    {hop.server_name}
                  </span>
                  <span className="text-xs font-mono text-slate-400 break-all">
                    ({hop.server_ip})
                  </span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {formatRTT(hop.rtt)}
                  {hop.authoritative && (
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-semibold">
                      AA (Authoritative)
                    </span>
                  )}
                  {hop.has_dnssec && (
                    <span className="text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800 text-[10px] font-semibold">
                      DNSSEC ({hop.rrsig_count} RRSIG)
                    </span>
                  )}
                </div>
              </div>

              {/* Flags */}
              <div className="flex flex-wrap gap-1.5 mb-2.5">
                {hop.flags?.rd && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">RD</span>
                )}
                {hop.flags?.ra && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">RA</span>
                )}
                {hop.flags?.tc && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900 text-amber-300">TC</span>
                )}
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400">
                  RCODE: {hop.rcode_str || hop.rcode}
                </span>
              </div>

              {/* Referral Details */}
              {hop.delegation && hop.delegation.length > 0 && (
                <div className="mt-2 text-xs text-slate-400">
                  <span className="text-slate-500 font-medium">Delegation to:</span>{' '}
                  <span className="font-mono text-slate-300">
                    {hop.delegation.slice(0, 4).join(', ')}
                    {hop.delegation.length > 4 && ` +${hop.delegation.length - 4} more`}
                  </span>
                </div>
              )}

              {/* Glue Details */}
              {hop.glue && hop.glue.length > 0 && (
                <div className="mt-1 text-xs text-slate-400">
                  <span className="text-slate-500 font-medium">Glue Records:</span>{' '}
                  <span className="font-mono text-slate-400">
                    {hop.glue.slice(0, 3).join(', ')}
                    {hop.glue.length > 3 && ` +${hop.glue.length - 3} more`}
                  </span>
                </div>
              )}

              {/* Errors */}
              {hop.error && (
                <div className="mt-2 text-xs text-rose-400 bg-rose-950/40 p-2 rounded border border-rose-900/50">
                  {hop.error}
                </div>
              )}
            </div>
          </div>
        ))}

        {/* Final Answers Card */}
        {data.final_answers && data.final_answers.length > 0 && (
          <div className="relative group">
            <div className="absolute -left-[27px] top-3.5 w-5 h-5 rounded-full bg-emerald-500 flex items-center justify-center text-[10px] font-bold text-slate-950 shadow-md">
              ✔
            </div>
            <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/60 shadow-lg">
              <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-2">
                Authoritative Answer Set
              </h4>
              <div className="space-y-1.5 font-mono text-xs">
                {data.final_answers.map((ans, idx) => (
                  <div key={idx} className="flex flex-wrap items-baseline gap-3 p-2 rounded bg-slate-900/60 border border-emerald-900/40">
                    <span className="px-1.5 py-0.5 rounded bg-emerald-900/80 text-emerald-200 text-[11px] font-bold">
                      {ans.type}
                    </span>
                    <span className="text-slate-400 text-[11px]">TTL: {ans.ttl}s</span>
                    <span className="text-emerald-300 font-medium break-all">{ans.data}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
