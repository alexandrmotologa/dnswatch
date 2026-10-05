import React from 'react';
import { ValidationResult } from '../types';

interface DnssecChainProps {
  data?: ValidationResult;
  loading: boolean;
}

export const DnssecChain: React.FC<DnssecChainProps> = ({ data, loading }) => {
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-slate-400 space-y-3">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm">Validating DNSSEC chain of trust from Root anchor to domain...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-8 text-center text-slate-500 text-sm">
        No DNSSEC validation data available. Enter a domain and run analysis.
      </div>
    );
  }

  const isSecure = data.overall_status === 'SECURE';
  const isBogus = data.overall_status === 'BOGUS';

  return (
    <div className="space-y-6">
      {/* Overall Status Banner */}
      <div
        className={`p-5 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-lg ${
          isSecure
            ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
            : isBogus
            ? 'bg-rose-950/40 border-rose-800/80 text-rose-200'
            : 'bg-amber-950/40 border-amber-800/80 text-amber-200'
        }`}
      >
        <div className="flex items-center gap-3.5">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
              isSecure
                ? 'bg-emerald-500/20 text-emerald-400'
                : isBogus
                ? 'bg-rose-500/20 text-rose-400'
                : 'bg-amber-500/20 text-amber-400'
            }`}
          >
            {isSecure ? (
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            ) : isBogus ? (
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            ) : (
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
              </svg>
            )}
          </div>
          <div>
            <h3 className="text-base font-bold tracking-tight">
              {isSecure
                ? 'SECURE — Cryptographic Trust Chain Verified'
                : isBogus
                ? 'BOGUS — DNSSEC Signature or Digest Validation Failed'
                : 'INSECURE — Zone or Parent Delegation is Unsigned'}
            </h3>
            <p className="text-xs opacity-80 font-mono">
              Domain: {data.domain} | Evaluated at {new Date(data.checked_at).toLocaleTimeString()}
            </p>
          </div>
        </div>

        <span
          className={`px-3 py-1 rounded-full text-xs font-bold tracking-wider font-mono uppercase ${
            isSecure
              ? 'bg-emerald-500 text-slate-950'
              : isBogus
              ? 'bg-rose-500 text-white'
              : 'bg-amber-500 text-slate-950'
          }`}
        >
          {data.overall_status}
        </span>
      </div>

      {/* Trust Ladder Nodes */}
      <div className="space-y-4">
        {(data.chain || []).map((node, idx) => {
          const isNodeSecure = node.status === 'SECURE';
          const isNodeBogus = node.status === 'BOGUS';
          const algorithms = node.algorithms || [];
          const kskTags = node.ksk_key_tags || [];
          const zskTags = node.zsk_key_tags || [];
          const errors = node.errors || [];
          const warnings = node.warnings || [];

          return (
            <div
              key={node.zone}
              className="p-3.5 sm:p-5 rounded-xl bg-slate-900/70 border border-slate-800 shadow-lg space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="w-6 h-6 rounded-lg bg-indigo-950 text-indigo-400 border border-indigo-800 flex items-center justify-center text-xs font-mono font-bold shrink-0">
                    {idx + 1}
                  </span>
                  <span className="text-sm font-bold font-mono text-slate-100 break-all">
                    Zone: {node.zone === '.' ? '. (Root Zone Trust Anchor)' : node.zone}
                  </span>
                </div>
                <span
                  className={`px-2.5 py-0.5 rounded text-[11px] font-bold font-mono ${
                    isNodeSecure
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : isNodeBogus
                      ? 'bg-rose-950 text-rose-300 border border-rose-800'
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}
                >
                  {node.status}
                </span>
              </div>

              {/* Grid of cryptographic properties */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 sm:gap-3 text-xs">
                {/* Algorithms */}
                <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Algorithms
                  </span>
                  <span className="font-mono text-slate-200 block truncate" title={algorithms.join(', ')}>
                    {algorithms.length > 0 ? algorithms.join(', ') : 'None'}
                  </span>
                </div>

                {/* Key Tags */}
                <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Key Tags (KSK / ZSK)
                  </span>
                  <span className="font-mono text-slate-200 block break-all">
                    {kskTags.length > 0 ? `KSK: ${kskTags.join(',')}` : ''}
                    {zskTags.length > 0 ? ` | ZSK: ${zskTags.join(',')}` : ''}
                    {kskTags.length === 0 && zskTags.length === 0 ? 'None' : ''}
                  </span>
                </div>

                {/* DS Match */}
                <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    Parent DS Digest
                  </span>
                  {node.has_ds ? (
                    <span className="font-mono text-emerald-400 font-medium block">
                      {node.digest_matched ? '✔ Digest Verified' : '✖ Mismatch'}
                    </span>
                  ) : (
                    <span className="font-mono text-slate-400 block">
                      {node.zone === '.' ? 'Self-Signed Root Anchor' : 'No DS Published'}
                    </span>
                  )}
                </div>

                {/* RRSIG Validity */}
                <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block font-semibold">
                    RRSIG Signature
                  </span>
                  {node.has_rrsig ? (
                    <span className={`font-mono block ${node.signatures_valid ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {node.signatures_valid ? '✔ Valid Signature' : '✖ Signature Invalid'}
                    </span>
                  ) : (
                    <span className="font-mono text-slate-400 block">Unsigned</span>
                  )}
                </div>
              </div>

              {/* Errors & Warnings */}
              {errors.length > 0 && (
                <div className="p-2.5 rounded bg-rose-950/40 border border-rose-900/60 text-xs text-rose-300 space-y-1">
                  {errors.map((e, i) => (
                    <div key={i}>• {e}</div>
                  ))}
                </div>
              )}
              {warnings.length > 0 && (
                <div className="p-2.5 rounded bg-amber-950/40 border border-amber-900/60 text-xs text-amber-300 space-y-1">
                  {warnings.map((w, i) => (
                    <div key={i}>▲ {w}</div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
