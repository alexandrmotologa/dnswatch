import React, { useState } from 'react';
import { PropagationSummary } from '../types';

interface PropagationMapProps {
  data?: PropagationSummary;
  loading: boolean;
}

export const PropagationMap: React.FC<PropagationMapProps> = ({ data, loading }) => {
  const [filterRegion, setFilterRegion] = useState<string>('ALL');

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-slate-400 space-y-3">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm">Querying 25+ worldwide DNS-over-HTTPS edge resolvers concurrently...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-8 text-center text-slate-500 text-sm">
        No propagation data available. Enter a domain and run analysis.
      </div>
    );
  }

  const formatRTT = (nanos: number) => {
    const ms = nanos / 1000000;
    let color = 'text-emerald-400';
    if (ms >= 150) color = 'text-rose-400';
    else if (ms >= 70) color = 'text-amber-400';
    return <span className={`font-mono text-xs font-medium ${color}`}>{ms.toFixed(1)}ms</span>;
  };

  // Unique regions
  const regions = ['ALL', ...Array.from(new Set(data.results.map((r) => r.provider.continent)))];

  const filteredResults = filterRegion === 'ALL'
    ? data.results
    : data.results.filter((r) => r.provider.continent === filterRegion);

  return (
    <div className="space-y-6">
      {/* Top Consensus Summary Card */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-5 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="md:col-span-2 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Global Propagation Consensus
            </span>
            <span className="text-lg font-bold font-mono text-emerald-400">
              {data.propagation_rate.toFixed(1)}%
            </span>
          </div>
          {/* Progress bar */}
          <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden p-0.5 border border-slate-700/50">
            <div
              className="h-full bg-gradient-to-r from-emerald-500 to-sky-400 rounded-full transition-all duration-500"
              style={{ width: `${Math.min(100, data.propagation_rate)}%` }}
            ></div>
          </div>
          <div className="text-xs text-slate-400 flex items-center justify-between pt-1 font-mono">
            <span>
              {data.success_count} / {data.total_tested} Nodes Responded
            </span>
            {data.consensus_answers.length > 0 && (
              <span className="text-indigo-300 font-medium truncate max-w-xs">
                Consensus: {data.consensus_answers.join(', ')}
              </span>
            )}
          </div>
        </div>

        {/* Latency stats */}
        <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-700/40 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider block">Average Latency</span>
          <div className="text-xl font-bold font-mono text-slate-100">
            {(data.avg_rtt / 1000000).toFixed(1)}ms
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Worldwide mean RTT</span>
        </div>

        <div className="p-3.5 rounded-lg bg-slate-800/40 border border-slate-700/40 space-y-1">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider block">Latency Span</span>
          <div className="text-xl font-bold font-mono text-slate-100">
            {(data.min_rtt / 1000000).toFixed(0)} - {(data.max_rtt / 1000000).toFixed(0)}ms
          </div>
          <span className="text-[11px] text-slate-500 font-mono">Fastest to slowest edge</span>
        </div>
      </div>

      {/* Region Filter Bar */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-500 font-medium mr-1 shrink-0">Filter Continent:</span>
        {regions.map((reg) => (
          <button
            key={reg}
            type="button"
            onClick={() => setFilterRegion(reg)}
            className={`px-3 py-1 rounded-lg font-medium transition-all shrink-0 cursor-pointer ${
              filterRegion === reg
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {reg}
          </button>
        ))}
      </div>

      {/* Vantage Points Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-400 font-semibold tracking-wider uppercase text-[10px]">
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Provider</th>
                <th className="py-3 px-4">Location</th>
                <th className="py-3 px-4">Region</th>
                <th className="py-3 px-4">Latency</th>
                <th className="py-3 px-4">TTL</th>
                <th className="py-3 px-4">Resolved Answer</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredResults.map((node) => {
                const answersStr = node.answers.map((a) => a.data).join(', ');
                return (
                  <tr key={node.provider.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 px-4">
                      {node.error ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/80 text-rose-300 border border-rose-800/50">
                          ✖ TIMEOUT
                        </span>
                      ) : node.matched_consensus ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800/50">
                          ✔ MATCH
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/50">
                          ▲ DIVERGENT
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-4 font-sans font-medium text-slate-200">
                      {node.provider.name}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {node.provider.city}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {node.provider.region}
                    </td>
                    <td className="py-2.5 px-4">
                      {formatRTT(node.rtt)}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {node.ttl > 0 ? `${node.ttl}s` : '-'}
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 truncate max-w-xs" title={answersStr || node.error}>
                      {node.error ? (
                        <span className="text-slate-500 font-sans italic">{node.error}</span>
                      ) : (
                        <span className="text-slate-100">{answersStr || '<empty>'}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
