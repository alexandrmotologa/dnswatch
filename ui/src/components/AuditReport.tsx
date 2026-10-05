import React, { useState } from 'react';
import { AuditReport as AuditReportType, Severity } from '../types';

interface AuditReportProps {
  data?: AuditReportType;
  loading: boolean;
}

export const AuditReport: React.FC<AuditReportProps> = ({ data, loading }) => {
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-slate-400 space-y-3">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm">Auditing SPF, DMARC, MX hygiene, subdomain takeover risks, and NS consistency...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-8 text-center text-slate-500 text-sm">
        No security audit data available. Enter a domain and run analysis.
      </div>
    );
  }

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'bg-emerald-500 text-slate-950 border-emerald-400';
      case 'B':
        return 'bg-teal-500 text-slate-950 border-teal-400';
      case 'C':
        return 'bg-amber-500 text-slate-950 border-amber-400';
      case 'D':
        return 'bg-orange-500 text-slate-950 border-orange-400';
      default:
        return 'bg-rose-500 text-white border-rose-400';
    }
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-800">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-950 text-sky-300 border border-sky-800">LOW</span>;
      case 'GOOD':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">PASS</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">INFO</span>;
    }
  };

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const findingsList = data.findings || [];
  const filteredFindings = filterSeverity === 'ALL'
    ? findingsList
    : findingsList.filter((f) => f.severity === filterSeverity);

  return (
    <div className="space-y-6">
      {/* Scorecard Header */}
      <div className="p-4 sm:p-6 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5 sm:gap-6 shadow-xl">
        <div className="flex flex-col sm:flex-row items-center sm:items-start text-center sm:text-left gap-4 sm:gap-5 w-full lg:w-auto">
          {/* Grade Badge */}
          <div
            className={`w-16 h-16 sm:w-20 sm:h-20 rounded-2xl border-2 flex flex-col items-center justify-center font-bold shadow-lg shrink-0 ${getGradeColor(
              data.grade
            )}`}
          >
            <span className="text-2xl sm:text-3xl leading-none">{data.grade}</span>
            <span className="text-[9px] sm:text-[10px] uppercase tracking-wider mt-1 opacity-90">Grade</span>
          </div>

          <div className="space-y-1 w-full sm:w-auto">
            <h3 className="text-base sm:text-lg font-bold text-slate-100">
              Domain Health & Security: {data.score}/100
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Domain: {data.domain} | Scanned at {new Date(data.checked_at).toLocaleTimeString()}
            </p>
            <div className="w-full sm:w-64 h-2.5 bg-slate-800 rounded-full overflow-hidden mt-2 border border-slate-700/50 mx-auto sm:mx-0">
              <div
                className="h-full bg-gradient-to-r from-rose-500 via-amber-500 to-emerald-500 rounded-full transition-all duration-500"
                style={{ width: `${data.score}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* Quick check pill indicators */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs w-full lg:w-auto">
          <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
            <span className="text-[10px] text-slate-500 block font-semibold">SPF Protocol</span>
            <span className="font-mono text-slate-200 font-medium">{data.spf_status}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
            <span className="text-[10px] text-slate-500 block font-semibold">DMARC Policy</span>
            <span className="font-mono text-slate-200 font-medium">{data.dmarc_status}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
            <span className="text-[10px] text-slate-500 block font-semibold">MX Mail Exchanger</span>
            <span className="font-mono text-slate-200 font-medium">{data.mx_status}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
            <span className="text-[10px] text-slate-500 block font-semibold">Subdomain Takeover</span>
            <span className={`font-mono font-medium ${data.takeover_risk ? 'text-rose-400' : 'text-emerald-400'}`}>
              {data.takeover_risk ? 'VULNERABLE' : 'SECURE'}
            </span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40 col-span-2 sm:col-span-1">
            <span className="text-[10px] text-slate-500 block font-semibold">NS Zone Parity</span>
            <span className={`font-mono font-medium ${data.ns_consistency ? 'text-emerald-400' : 'text-amber-400'}`}>
              {data.ns_consistency ? 'SYNCHRONIZED' : 'INCONSISTENT'}
            </span>
          </div>
        </div>
      </div>

      {/* Severity Filter Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-500 font-medium mr-1 shrink-0">Filter Findings:</span>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'GOOD'].map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setFilterSeverity(s)}
            className={`px-3 py-1 rounded-lg font-medium transition-all shrink-0 cursor-pointer ${
              filterSeverity === s
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.map((f, idx) => (
          <div
            key={idx}
            className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-colors shadow-md space-y-2"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {getSeverityBadge(f.severity)}
                <h4 className="text-sm font-semibold text-slate-100">{f.title}</h4>
              </div>
              <span className="text-[11px] font-mono text-slate-500 px-2 py-0.5 rounded bg-slate-800/60">
                {f.category}
              </span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

            {f.record && (
              <div className="p-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-400 break-all">
                <span className="text-slate-600 select-none mr-2">Record:</span>
                {f.record}
              </div>
            )}

            {f.recommendation && (
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 p-2.5 rounded-lg bg-indigo-950/20 border border-indigo-900/40 text-xs">
                <div className="text-indigo-300 leading-relaxed">
                  <span className="font-semibold text-indigo-400 select-none mr-1.5">Action:</span>
                  {f.recommendation}
                </div>
                <button
                  type="button"
                  onClick={() => handleCopy(f.recommendation, idx)}
                  className="self-end sm:self-auto px-2.5 py-1 rounded bg-indigo-900/40 hover:bg-indigo-900/70 text-indigo-200 text-[11px] font-medium transition-colors shrink-0 cursor-pointer"
                >
                  {copiedIdx === idx ? 'Copied!' : 'Copy Fix'}
                </button>
              </div>
            )}
          </div>
        ))}

        {filteredFindings.length === 0 && (
          <div className="p-8 text-center text-slate-500 text-xs bg-slate-900/40 rounded-xl border border-slate-800">
            No findings for the selected filter ({filterSeverity}).
          </div>
        )}
      </div>
    </div>
  );
};
