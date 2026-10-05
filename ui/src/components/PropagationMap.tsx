import React, { useState } from 'react';
import { PropagationSummary, NodeResult, RecordInfo } from '../types';

interface PropagationMapProps {
  data?: PropagationSummary;
  loading: boolean;
}

// Geographic layout coordinates on a 960x480 SVG projection canvas
const NODE_COORDINATES: Record<string, { x: number; y: number }> = {
  // Cities
  'Ashburn, VA': { x: 275, y: 168 },
  'Toronto': { x: 268, y: 150 },
  'New York, NY': { x: 285, y: 162 },
  'Frankfurt': { x: 508, y: 138 },
  'Amsterdam': { x: 496, y: 126 },
  'Zurich': { x: 503, y: 147 },
  'Prague': { x: 520, y: 136 },
  'Helsinki': { x: 546, y: 92 },
  'Paris': { x: 486, y: 142 },
  'London': { x: 476, y: 132 },
  'Tokyo': { x: 842, y: 184 },
  'Taipei': { x: 806, y: 222 },
  'Athens': { x: 542, y: 176 },
  'Osaka': { x: 832, y: 188 },
  'São Paulo': { x: 352, y: 352 },
  'Santiago': { x: 288, y: 376 },
  'Johannesburg': { x: 556, y: 346 },
  'Dubai': { x: 638, y: 216 },

  // Global Anycast hub distribution
  'cloudflare': { x: 218, y: 178 },
  'google': { x: 236, y: 192 },
  'quad9': { x: 498, y: 156 },
  'opendns': { x: 254, y: 164 },
  'adguard': { x: 532, y: 120 },
  'mullvad': { x: 518, y: 104 },
  'controld': { x: 278, y: 148 },
};

function getNodePosition(node: NodeResult, index: number): { x: number; y: number } {
  if (NODE_COORDINATES[node.provider.id]) {
    return NODE_COORDINATES[node.provider.id];
  }
  if (NODE_COORDINATES[node.provider.city]) {
    return NODE_COORDINATES[node.provider.city];
  }
  // Fallbacks by continent with jitter
  const jitter = (index % 5) * 8 - 16;
  switch (node.provider.continent) {
    case 'North America':
      return { x: 250 + jitter, y: 160 + jitter };
    case 'Europe':
      return { x: 510 + jitter, y: 135 + jitter };
    case 'Asia':
      return { x: 800 + jitter, y: 200 + jitter };
    case 'South America':
      return { x: 330 + jitter, y: 340 + jitter };
    case 'Africa':
      return { x: 540 + jitter, y: 320 + jitter };
    case 'Middle East':
      return { x: 630 + jitter, y: 215 + jitter };
    default:
      return { x: 450 + (index * 25) % 400, y: 200 + (index * 15) % 150 };
  }
}

export const PropagationMap: React.FC<PropagationMapProps> = ({ data, loading }) => {
  const [filterRegion, setFilterRegion] = useState<string>('ALL');
  const [hoveredNode, setHoveredNode] = useState<NodeResult | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-16 text-slate-400 space-y-4">
        <div className="w-10 h-10 border-3 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-sm font-medium">Interrogating 25+ worldwide DNS edge vantage points in parallel...</p>
        <span className="text-xs text-slate-500">Querying Tokyo, London, Frankfurt, Ashburn, São Paulo, Johannesburg, Dubai</span>
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
              {data.success_count} / {data.total_tested} Edge Resolvers Responded
            </span>
            {data.consensus_answers.length > 0 && (
              <span className="text-indigo-300 font-medium truncate max-w-xs" title={data.consensus_answers.join(', ')}>
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

      {/* World Map SVG Projection */}
      <div className="relative rounded-2xl border border-slate-800 bg-slate-950/80 p-4 overflow-hidden shadow-2xl">
        <div className="flex items-center justify-between mb-3 px-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <span>🌐</span> Edge Vantage Map
            </span>
            <span className="text-[11px] text-slate-500">
              (Click a pin to highlight in list below)
            </span>
          </div>
          {/* Status legend */}
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 ring-4 ring-emerald-500/20"></span>
              <span className="text-slate-300">Match</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 ring-4 ring-amber-500/20"></span>
              <span className="text-slate-300">Divergent</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 ring-4 ring-rose-500/20"></span>
              <span className="text-slate-300">Timeout</span>
            </div>
          </div>
        </div>

        {/* SVG Container */}
        <div className="relative w-full aspect-[2/1] max-h-[460px] bg-gradient-to-b from-slate-950 to-slate-900/90 rounded-xl border border-slate-800/60 overflow-hidden flex items-center justify-center">
          <svg
            viewBox="0 0 960 480"
            className="w-full h-full select-none"
            preserveAspectRatio="xMidYMid meet"
          >
            <defs>
              {/* Radial gradient for glowing pins */}
              <radialGradient id="emeraldGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#34d399" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
              </radialGradient>
              <radialGradient id="amberGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#fbbf24" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
              </radialGradient>
              <radialGradient id="roseGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#f87171" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
              </radialGradient>
            </defs>

            {/* Latitude & Longitude grid lines */}
            <g stroke="#1e293b" strokeWidth="0.75" strokeDasharray="3 3">
              <line x1="0" y1="120" x2="960" y2="120" />
              <line x1="0" y1="240" x2="960" y2="240" />
              <line x1="0" y1="360" x2="960" y2="360" />
              <line x1="240" y1="0" x2="240" y2="480" />
              <line x1="480" y1="0" x2="480" y2="480" />
              <line x1="720" y1="0" x2="720" y2="480" />
            </g>

            {/* Stylized world continent land masses */}
            <g fill="#1e293b" fillOpacity="0.45" stroke="#334155" strokeWidth="0.8">
              {/* North America */}
              <path d="M120 70 L210 50 L280 60 L330 110 L300 150 L270 170 L230 200 L210 230 L190 220 L180 180 L140 160 L110 120 Z" />
              {/* Greenland */}
              <path d="M340 30 L400 35 L420 70 L370 85 L330 65 Z" />
              {/* South America */}
              <path d="M250 250 L310 240 L370 290 L360 360 L320 420 L270 380 L250 310 Z" />
              {/* Europe */}
              <path d="M460 90 L530 80 L560 110 L540 150 L480 160 L450 140 L460 110 Z" />
              {/* Africa */}
              <path d="M460 180 L550 180 L590 240 L570 330 L520 380 L480 340 L440 260 L440 210 Z" />
              {/* Asia */}
              <path d="M570 80 L760 70 L870 120 L860 190 L790 240 L720 230 L660 210 L580 170 Z" />
              {/* Australia */}
              <path d="M780 300 L870 310 L880 370 L810 400 L760 360 Z" />
              {/* UK / Iceland / Japan islands */}
              <path d="M455 115 L470 120 L460 135 Z" />
              <path d="M835 160 L855 175 L845 205 L830 180 Z" />
            </g>

            {/* Edge Nodes as Animated Pins */}
            {data.results.map((node, i) => {
              const pos = getNodePosition(node, i);
              const isSelected = selectedNodeId === node.provider.id;
              const isHovered = hoveredNode?.provider.id === node.provider.id;

              let fillColor = '#10b981';
              let ringColor = 'rgba(16, 185, 129, 0.3)';
              if (node.error) {
                fillColor = '#ef4444';
                ringColor = 'rgba(239, 68, 68, 0.3)';
              } else if (!node.matched_consensus) {
                fillColor = '#f59e0b';
                ringColor = 'rgba(245, 158, 11, 0.3)';
              }

              return (
                <g
                  key={node.provider.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  className="cursor-pointer transition-transform duration-200"
                  onClick={() => setSelectedNodeId(isSelected ? null : node.provider.id)}
                  onMouseEnter={() => setHoveredNode(node)}
                  onMouseLeave={() => setHoveredNode(null)}
                >
                  {/* Outer pulse wave */}
                  <circle
                    r={isSelected || isHovered ? 12 : 7}
                    fill={fillColor}
                    fillOpacity="0.2"
                    className="animate-ping"
                    style={{ animationDuration: '3s' }}
                  />

                  {/* Ring highlight */}
                  <circle
                    r={isSelected || isHovered ? 8 : 5}
                    fill="none"
                    stroke={ringColor}
                    strokeWidth={isSelected ? 3 : 2}
                  />

                  {/* Core pin dot */}
                  <circle
                    r={isSelected || isHovered ? 4.5 : 3}
                    fill={fillColor}
                  />

                  {/* Label for highlighted/hovered nodes */}
                  {(isHovered || isSelected) && (
                    <g transform="translate(0, -14)">
                      <rect
                        x="-45"
                        y="-16"
                        width="90"
                        height="16"
                        rx="4"
                        fill="#0f172a"
                        stroke="#334155"
                        strokeWidth="1"
                      />
                      <text
                        x="0"
                        y="-5"
                        textAnchor="middle"
                        fill="#f8fafc"
                        fontSize="9"
                        fontFamily="monospace"
                        fontWeight="bold"
                      >
                        {node.provider.city} ({(node.rtt / 1000000).toFixed(0)}ms)
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </svg>

          {/* Floating inspect tooltip when hovering a node */}
          {hoveredNode && (
            <div className="absolute bottom-3 left-3 bg-slate-900/95 border border-slate-700/80 rounded-lg p-2.5 text-xs shadow-2xl backdrop-blur-md max-w-sm pointer-events-none animate-in fade-in duration-150">
              <div className="flex items-center justify-between gap-3 mb-1">
                <span className="font-bold text-slate-100">{hoveredNode.provider.name}</span>
                <span className="font-mono text-[11px] text-emerald-400">
                  {(hoveredNode.rtt / 1000000).toFixed(1)}ms
                </span>
              </div>
              <div className="text-[11px] text-slate-400 space-y-0.5">
                <div>Location: <span className="text-slate-200">{hoveredNode.provider.city}, {hoveredNode.provider.country}</span></div>
                <div>Status: <span className={hoveredNode.error ? 'text-rose-400 font-bold' : hoveredNode.matched_consensus ? 'text-emerald-400' : 'text-amber-400'}>
                  {hoveredNode.error ? hoveredNode.error : hoveredNode.matched_consensus ? 'Matches Consensus' : 'Divergent Answer'}
                </span></div>
                {hoveredNode.answers.length > 0 && (
                  <div className="truncate font-mono text-slate-300">
                    Ans: {hoveredNode.answers.map((a: RecordInfo) => a.data).join(', ')}
                  </div>
                )}
              </div>
            </div>
          )}
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
                const isSelected = selectedNodeId === node.provider.id;
                return (
                  <tr
                    key={node.provider.id}
                    onClick={() => setSelectedNodeId(isSelected ? null : node.provider.id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-indigo-950/60 border-l-2 border-indigo-500'
                        : 'hover:bg-slate-800/30'
                    }`}
                  >
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
