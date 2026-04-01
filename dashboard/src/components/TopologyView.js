'use client';
import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { motion, AnimatePresence } from 'framer-motion';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const TYPE_META = {
  aws_iam_user:              { label: 'IAM User',       color: '#a78bfa', icon: '👤', group: 'Identity'  },
  aws_iam_policy:            { label: 'IAM Policy',     color: '#7c3aed', icon: '📋', group: 'Identity'  },
  aws_s3_bucket:             { label: 'S3 Bucket',      color: '#60a5fa', icon: '🪣', group: 'Storage'   },
  aws_ec2_instance:          { label: 'EC2 Instance',   color: '#34d399', icon: '🖥️', group: 'Compute'   },
  aws_security_group:        { label: 'Security Group', color: '#f59e0b', icon: '🛡️', group: 'Network'   },
  aws_vpc:                   { label: 'VPC',            color: '#22d3ee', icon: '🌐', group: 'Network'   },
  aws_rds_instance:          { label: 'RDS',            color: '#fb923c', icon: '🗄️', group: 'Database'  },
  aws_lambda_function:       { label: 'Lambda',         color: '#e879f9', icon: '⚡', group: 'Compute'   },
  'aws_ec2_internet-gateway':{ label: 'IGW',            color: '#38bdf8', icon: '🔌', group: 'Network'   },
  aws_ec2_subnet:            { label: 'Subnet',         color: '#6ee7b7', icon: '🔗', group: 'Network'   },
  aws_secretsmanager_secret: { label: 'Secret',         color: '#f87171', icon: '🔑', group: 'Security'  },
};
const defaultMeta = (t) => ({ label: t.replace('aws_','').replace(/_/g,' '), color: '#94a3b8', icon: '☁️', group: 'Other' });
const getMeta = (t) => TYPE_META[t] || defaultMeta(t);

const NODE_R = 22;

const GROUP_LAYOUT = {
  Identity: { col: 0, row: 0 },
  Compute:  { col: 1, row: 0 },
  Storage:  { col: 2, row: 0 },
  Network:  { col: 1, row: 1 },
  Database: { col: 2, row: 1 },
  Security: { col: 0, row: 1 },
  Other:    { col: 1, row: 2 },
};

// ── Inspector ─────────────────────────────────────────────────────────────────
function Inspector({ node, onClose }) {
  if (!node) return null;
  const m = getMeta(node.type);
  const fail = node.status === 'fail';
  return (
    <motion.div
      initial={{ x: 380, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 380, opacity: 0 }}
      transition={{ type: 'spring', damping: 26, stiffness: 200 }}
      style={{
        position: 'absolute', top: 0, right: 0, bottom: 0, width: 380,
        background: '#07101f', borderLeft: '1px solid #1a2a4a',
        display: 'flex', flexDirection: 'column', zIndex: 60,
        boxShadow: '-24px 0 60px rgba(0,0,0,0.85)',
      }}
    >
      <div style={{ padding: '20px 22px 16px', borderBottom: '1px solid #1a2a4a', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 46, height: 46, borderRadius: 13,
              background: `${m.color}15`, border: `2px solid ${m.color}45`,
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22,
              boxShadow: `0 0 20px ${m.color}20`,
            }}>{m.icon}</div>
            <div>
              <div style={{ color: '#f1f5f9', fontSize: 13, fontWeight: 700, maxWidth: 230, wordBreak: 'break-all', lineHeight: 1.4 }}>{node.label}</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
                <span style={{ color: m.color, fontSize: 11, fontWeight: 600 }}>{m.label}</span>
                <span style={{ color: '#2a3a56', fontSize: 11 }}>·</span>
                <span style={{ color: '#475569', fontSize: 11 }}>{node.region || 'global'}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{
            background: '#121f36', border: '1px solid #1a2a4a', color: '#475569',
            width: 28, height: 28, borderRadius: 8, cursor: 'pointer', fontSize: 16,
            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          }}>×</button>
        </div>
        <div style={{
          padding: '10px 14px', borderRadius: 10,
          background: fail ? 'rgba(239,68,68,0.07)' : 'rgba(16,185,129,0.07)',
          border: `1px solid ${fail ? '#ef444428' : '#10b98128'}`,
          display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <div style={{ width: 34, height: 34, borderRadius: '50%', flexShrink: 0, fontSize: 16, background: fail ? 'rgba(239,68,68,0.12)' : 'rgba(16,185,129,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {fail ? '⚠️' : '✅'}
          </div>
          <div>
            <div style={{ color: fail ? '#ef4444' : '#10b981', fontSize: 13, fontWeight: 700 }}>{fail ? 'Compliance Violation' : 'Compliant'}</div>
            <div style={{ color: '#475569', fontSize: 11, marginTop: 2 }}>{fail ? 'One or more CIS benchmarks failed' : 'Meets current security baseline'}</div>
          </div>
        </div>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 22px' }}>
        <SLabel>Identity</SLabel>
        <SCard><KV k="ID" v={node.id} mono /><KV k="Type" v={node.type} /><KV k="Group" v={node.group} /><KV k="Region" v={node.region || 'global'} /></SCard>
        {node.config && Object.keys(node.config).length > 0 && (
          <><SLabel style={{ marginTop: 16 }}>Configuration</SLabel>
          <SCard>{Object.entries(node.config).slice(0, 12).map(([k, v]) => <KV key={k} k={k.replace(/_/g,' ')} v={typeof v === 'object' ? JSON.stringify(v).slice(0,70) : String(v).slice(0,90)} />)}</SCard></>
        )}
      </div>
      <div style={{ padding: '14px 22px', borderTop: '1px solid #1a2a4a', flexShrink: 0 }}>
        <button style={{ width: '100%', padding: '10px 0', borderRadius: 9, background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', color: '#3b82f6', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>Open in AWS Console ↗</button>
      </div>
    </motion.div>
  );
}

const SLabel = ({ children, style }) => <div style={{ color: '#2a3a56', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.1px', marginBottom: 7, ...style }}>{children}</div>;
const SCard = ({ children }) => <div style={{ background: '#060e1c', borderRadius: 9, border: '1px solid #131f33', overflow: 'hidden', marginBottom: 4 }}>{children}</div>;
const KV = ({ k, v, mono }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '7px 12px', borderBottom: '1px solid #0c1828' }}>
    <span style={{ color: '#374151', fontSize: 11, flexShrink: 0 }}>{k}</span>
    <span style={{ color: mono ? '#7dd3fc' : '#6b7280', fontSize: 11, fontFamily: mono ? 'monospace' : 'inherit', textAlign: 'right', wordBreak: 'break-all', maxWidth: 200 }}>{v ?? '—'}</span>
  </div>
);

// ── Left panel ────────────────────────────────────────────────────────────────
function EntityPanel({ groups, typeCounts, activeFilters, onToggleFilter, meta }) {
  const [collapsed, setCollapsed] = useState({});
  const toggle = (g) => setCollapsed(p => ({ ...p, [g]: !p[g] }));
  return (
    <div style={{ width: 228, flexShrink: 0, background: '#050d1a', borderRight: '1px solid #131f33', display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '16px 16px 12px', borderBottom: '1px solid #131f33' }}>
        <div style={{ color: '#2a3a56', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 4 }}>Resources</div>
        <div style={{ color: '#f1f5f9', fontSize: 26, fontWeight: 800, lineHeight: 1 }}>{meta.total || 0}</div>
        <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 5px #10b981' }} />
            <span style={{ color: '#10b981', fontSize: 11, fontWeight: 600 }}>{meta.compliant}</span>
            <span style={{ color: '#2a3a56', fontSize: 11 }}>ok</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 5px #ef4444', animation: 'pulse 2s infinite' }} />
            <span style={{ color: '#ef4444', fontSize: 11, fontWeight: 600 }}>{meta.violations}</span>
            <span style={{ color: '#2a3a56', fontSize: 11 }}>violations</span>
          </div>
        </div>
      </div>
      <div style={{ padding: '7px 14px 6px', borderBottom: '1px solid #131f33', color: '#2a3a56', fontSize: 10 }}>Click type to filter · Scroll to zoom</div>
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {groups.map(g => {
          const isCol = collapsed[g.name];
          const types = Object.entries(typeCounts).filter(([t]) => getMeta(t).group === g.name);
          if (!types.length) return null;
          return (
            <div key={g.name}>
              <div onClick={() => toggle(g.name)} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 16px', cursor: 'pointer', userSelect: 'none', color: '#374151', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.9px', borderTop: '1px solid #0c1828' }}>
                <span>{g.name}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {g.violations > 0 && <span style={{ background: '#ef444412', color: '#ef4444', fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 10, border: '1px solid #ef444425' }}>{g.violations}</span>}
                  <span style={{ color: '#2a3a56', fontSize: 9 }}>{isCol ? '▶' : '▼'}</span>
                </div>
              </div>
              {!isCol && types.map(([rtype, count]) => {
                const m = getMeta(rtype);
                const active = activeFilters.size === 0 || activeFilters.has(rtype);
                return (
                  <div key={rtype} onClick={() => onToggleFilter(rtype)} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '5px 12px 5px 20px', cursor: 'pointer', opacity: active ? 1 : 0.25, background: active ? `${m.color}06` : 'transparent', margin: '1px 6px', borderRadius: 7, transition: 'all 0.15s' }}>
                    <div style={{ width: 26, height: 26, borderRadius: 8, flexShrink: 0, fontSize: 12, background: `${m.color}12`, border: `1.5px solid ${m.color}35`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{m.icon}</div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ color: '#9ca3af', fontSize: 12, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{m.label}</div>
                    </div>
                    <span style={{ color: '#374151', fontSize: 12, fontWeight: 700, flexShrink: 0 }}>{count}</span>
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function TopologyView() {
  const svgRef  = useRef(null);
  const simRef  = useRef(null);
  const zoomRef = useRef(null);
  const gRef    = useRef(null);

  const [data, setData]               = useState(null);
  const [loading, setLoading]         = useState(true);
  const [selected, setSelected]       = useState(null);
  const [activeFilters, setActiveFilters] = useState(new Set());
  const [search, setSearch]           = useState('');
  const [lastSync, setLastSync]       = useState(null);
  const [showViolations, setShowViolations] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/topology`);
      const j = await r.json();
      setData(j);
      setLastSync(new Date());
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchData();
    let ws;
    try {
      ws = new WebSocket(`${API.replace('http','ws')}/api/ws/topology`);
      ws.onmessage = ev => { try { if (JSON.parse(ev.data).type === 'RESOURCE_UPDATED') fetchData(); } catch {} };
    } catch {}
    return () => ws?.close();
  }, [fetchData]);

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const W = svgRef.current.clientWidth  || 1000;
    const H = svgRef.current.clientHeight || 700;

    let nodes = (data.nodes || []).filter(n => {
      if (activeFilters.size > 0 && !activeFilters.has(n.type)) return false;
      if (showViolations && n.status !== 'fail') return false;
      if (search) { const q = search.toLowerCase(); if (!n.label.toLowerCase().includes(q) && !n.type.toLowerCase().includes(q)) return false; }
      return true;
    });
    const nodeIds = new Set(nodes.map(n => n.id));
    let edges = (data.edges || []).filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));
    nodes = nodes.map(n => ({ ...n }));
    edges = edges.map(e => ({ ...e }));

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // ── Defs ──────────────────────────────────────────────────────────────────
    const defs = svg.append('defs');

    const fGlow = defs.append('filter').attr('id','glow').attr('x','-50%').attr('y','-50%').attr('width','200%').attr('height','200%');
    fGlow.append('feGaussianBlur').attr('stdDeviation','4').attr('result','b');
    const mg = fGlow.append('feMerge'); mg.append('feMergeNode').attr('in','b'); mg.append('feMergeNode').attr('in','SourceGraphic');

    [
      { id:'arr-sg',  color:'rgba(245,158,11,0.5)'  },
      { id:'arr-pol', color:'rgba(167,139,250,0.5)' },
      { id:'arr-vpc', color:'rgba(34,211,238,0.5)'  },
      { id:'arr-def', color:'rgba(51,65,85,0.4)'    },
    ].forEach(({ id, color }) => {
      defs.append('marker').attr('id', id).attr('viewBox','0 -4 10 8').attr('refX', NODE_R + 8).attr('refY', 0).attr('markerWidth', 5).attr('markerHeight', 5).attr('orient','auto')
        .append('path').attr('d','M0,-4L10,0L0,4').attr('fill', color);
    });

    // ── Layers ────────────────────────────────────────────────────────────────
    const g = svg.append('g').attr('class','root');
    gRef.current = g.node();

    const zoomBeh = d3.zoom().scaleExtent([0.04, 6]).on('zoom', ev => g.attr('transform', ev.transform));
    svg.call(zoomBeh);
    zoomRef.current = zoomBeh;

    // Group centers
    const allGroups = [...new Set(nodes.map(n => getMeta(n.type).group))];
    const cols = Math.max(2, Math.ceil(Math.sqrt(allGroups.length)));
    const SPREAD_X = 340, SPREAD_Y = 290;
    const groupCenters = {};
    allGroups.forEach((grp, i) => {
      const layout = GROUP_LAYOUT[grp];
      groupCenters[grp] = layout
        ? { x: (layout.col - 1) * SPREAD_X, y: (layout.row - 0.8) * SPREAD_Y }
        : { x: (i % cols - cols / 2) * SPREAD_X, y: (Math.floor(i / cols) - 1) * SPREAD_Y };
    });

    // Group zone halos
    const haloLayer = g.append('g');
    allGroups.forEach(grp => {
      const grpNodes = nodes.filter(n => getMeta(n.type).group === grp);
      if (!grpNodes.length) return;
      const center = groupCenters[grp];
      const r = Math.max(80, Math.sqrt(grpNodes.length) * 50 + 40);
      const color = getMeta(grpNodes[0].type).color;
      haloLayer.append('circle').attr('cx', center.x).attr('cy', center.y).attr('r', r)
        .attr('fill', `${color}05`).attr('stroke', `${color}12`).attr('stroke-width', 1.5).attr('stroke-dasharray', '5,4');
      haloLayer.append('text').attr('x', center.x).attr('y', center.y - r + 16).attr('text-anchor','middle')
        .attr('fill', `${color}45`).attr('font-size', 10).attr('font-weight','700').attr('letter-spacing','1.5px')
        .style('pointer-events','none').text(grp.toUpperCase());
    });

    // Edges
    const eColor = t => t === 'uses_sg' ? 'rgba(245,158,11,0.2)' : t === 'attached_to' ? 'rgba(167,139,250,0.2)' : t === 'contains' ? 'rgba(34,211,238,0.2)' : 'rgba(51,65,85,0.25)';
    const eMarker = t => t === 'uses_sg' ? 'arr-sg' : t === 'attached_to' ? 'arr-pol' : t === 'contains' ? 'arr-vpc' : 'arr-def';

    const link = g.append('g').selectAll('line').data(edges).join('line')
      .attr('stroke', d => eColor(d.type)).attr('stroke-width', 1)
      .attr('marker-end', d => `url(#${eMarker(d.type)})`);

    // Nodes
    const nodeG = g.append('g').selectAll('g').data(nodes).join('g')
      .attr('class','nd').style('cursor','pointer')
      .call(d3.drag()
        .on('start', (ev, d) => { if (!ev.active) simRef.current?.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag',  (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
        .on('end',   (ev, d) => { if (!ev.active) simRef.current?.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (ev, d) => { ev.stopPropagation(); setSelected(d); })
      .on('mouseover', function(ev, d) {
        d3.select(this).select('.body').attr('stroke-width', 2.5).attr('filter','url(#glow)');
        d3.select(this).select('.lbl').attr('opacity', 1);
      })
      .on('mouseout', function(ev, d) {
        d3.select(this).select('.body').attr('stroke-width', d.status === 'fail' ? 2 : 1.5).attr('filter', d.status === 'fail' ? 'url(#glow)' : null);
        d3.select(this).select('.lbl').attr('opacity', 0.6);
      });

    svg.on('click', () => setSelected(null));

    // Violation outer ring
    nodeG.filter(d => d.status === 'fail')
      .append('circle').attr('r', NODE_R + 8).attr('fill','none')
      .attr('stroke','#ef444430').attr('stroke-width', 2).attr('filter','url(#glow)');

    // Main circle
    nodeG.append('circle').attr('class','body').attr('r', NODE_R)
      .attr('fill', d => `${getMeta(d.type).color}16`)
      .attr('stroke', d => d.status === 'fail' ? '#ef4444' : getMeta(d.type).color)
      .attr('stroke-width', d => d.status === 'fail' ? 2 : 1.5)
      .attr('filter', d => d.status === 'fail' ? 'url(#glow)' : null);

    // Icon
    nodeG.append('text').attr('text-anchor','middle').attr('dominant-baseline','central')
      .attr('font-size', NODE_R * 0.88).style('user-select','none').style('pointer-events','none')
      .text(d => getMeta(d.type).icon);

    // Violation badge
    nodeG.filter(d => d.status === 'fail')
      .append('circle').attr('cx', NODE_R * 0.7).attr('cy', -NODE_R * 0.7)
      .attr('r', 5.5).attr('fill','#ef4444').attr('stroke','#040b16').attr('stroke-width', 1.5);

    // Label
    nodeG.append('text').attr('class','lbl').attr('y', NODE_R + 13).attr('text-anchor','middle')
      .attr('fill','#94a3b8').attr('font-size', 9.5).attr('opacity', 0.6)
      .style('pointer-events','none')
      .text(d => d.label.length > 16 ? d.label.slice(0, 14) + '…' : d.label);

    // ── Simulation ────────────────────────────────────────────────────────────
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id(d => d.id).distance(85).strength(0.35))
      .force('charge', d3.forceManyBody().strength(-400).distanceMax(600))
      .force('collision', d3.forceCollide(NODE_R + 20))
      .force('cluster_x', d3.forceX(d => groupCenters[getMeta(d.type).group]?.x ?? 0).strength(0.16))
      .force('cluster_y', d3.forceY(d => groupCenters[getMeta(d.type).group]?.y ?? 0).strength(0.16))
      .on('tick', () => {
        link.attr('x1', d => d.source.x||0).attr('y1', d => d.source.y||0)
            .attr('x2', d => d.target.x||0).attr('y2', d => d.target.y||0);
        nodeG.attr('transform', d => `translate(${d.x||0},${d.y||0})`);
      });

    simRef.current = sim;

    // Auto-fit
    const fitTimer = setTimeout(() => {
      if (!svgRef.current || !gRef.current) return;
      const box = gRef.current.getBBox();
      if (!box.width) return;
      const pad = 60;
      const s = Math.min((W-pad*2)/box.width, (H-pad*2)/box.height, 1.3);
      const tx = W/2 - s*(box.x + box.width/2);
      const ty = H/2 - s*(box.y + box.height/2);
      svg.transition().duration(900).call(zoomBeh.transform, d3.zoomIdentity.translate(tx,ty).scale(s));
    }, 2400);

    return () => { sim.stop(); clearTimeout(fitTimer); };
  }, [data, activeFilters, search, showViolations]);

  // Selected highlight
  useEffect(() => {
    if (!svgRef.current) return;
    d3.select(svgRef.current).selectAll('.nd .body')
      .attr('stroke-width', d => d.id === selected?.id ? 3 : d.status === 'fail' ? 2 : 1.5)
      .attr('filter', d => (d.id === selected?.id || d.status === 'fail') ? 'url(#glow)' : null);
  }, [selected]);

  const zoomIn  = () => d3.select(svgRef.current).transition().duration(280).call(zoomRef.current?.scaleBy, 1.45);
  const zoomOut = () => d3.select(svgRef.current).transition().duration(280).call(zoomRef.current?.scaleBy, 0.68);
  const fitAll  = () => {
    if (!svgRef.current || !gRef.current || !zoomRef.current) return;
    const W = svgRef.current.clientWidth || 1000, H = svgRef.current.clientHeight || 700;
    const box = gRef.current.getBBox();
    if (!box.width) return;
    const pad = 60, s = Math.min((W-pad*2)/box.width, (H-pad*2)/box.height, 1.5);
    d3.select(svgRef.current).transition().duration(500).call(zoomRef.current.transform, d3.zoomIdentity.translate(W/2 - s*(box.x+box.width/2), H/2 - s*(box.y+box.height/2)).scale(s));
  };

  const toggleFilter = useCallback((rtype) => {
    setActiveFilters(prev => { const n = new Set(prev); n.has(rtype) ? n.delete(rtype) : n.add(rtype); return n; });
  }, []);

  const meta       = data?.meta        || {};
  const groups     = data?.groups      || [];
  const typeCounts = data?.type_counts || {};

  return (
    <div style={{ width:'100%', height:'calc(100vh - 60px)', display:'flex', flexDirection:'column', background:'#030a14', fontFamily:'inherit' }}>

      {/* Topbar */}
      <div style={{ display:'flex', alignItems:'center', gap:12, padding:'9px 18px', borderBottom:'1px solid #131f33', flexShrink:0, background:'#050d1a' }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <div style={{ width:7, height:7, borderRadius:'50%', background:'#10b981', boxShadow:'0 0 7px #10b981', animation:'pulse 2s infinite' }} />
          <span style={{ color:'#f1f5f9', fontSize:14, fontWeight:700 }}>Infrastructure Graph</span>
          {lastSync && <span style={{ color:'#1e2e45', fontSize:11 }}>· {lastSync.toLocaleTimeString()}</span>}
        </div>

        {meta.total > 0 && (
          <div style={{ display:'flex', gap:6, marginLeft:6 }}>
            <Chip label="Total"      val={meta.total}      color="#3b82f6" />
            <Chip label="Compliant"  val={meta.compliant}  color="#10b981" />
            <Chip label="Violations" val={meta.violations} color="#ef4444" onClick={() => setShowViolations(v => !v)} active={showViolations} />
          </div>
        )}

        <div style={{ flex:1 }} />

        <div style={{ position:'relative' }}>
          <span style={{ position:'absolute', left:8, top:'50%', transform:'translateY(-50%)', color:'#1e2e45', fontSize:12 }}>🔍</span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search resources…"
            style={{ background:'#090f1e', border:'1px solid #131f33', borderRadius:8, color:'#cbd5e1', fontSize:12, padding:'6px 10px 6px 26px', width:195, outline:'none' }} />
        </div>

        {activeFilters.size > 0 && (
          <button onClick={() => setActiveFilters(new Set())} style={{ padding:'5px 11px', background:'#121f36', border:'1px solid #1a2a4a', borderRadius:7, color:'#94a3b8', fontSize:11, cursor:'pointer' }}>✕ Clear</button>
        )}

        <button onClick={fetchData} disabled={loading} style={{ display:'flex', alignItems:'center', gap:5, padding:'6px 12px', background:'#090f1e', border:'1px solid #131f33', borderRadius:8, color:'#475569', fontSize:12, cursor:'pointer' }}>
          <span style={{ display:'inline-block', animation: loading ? 'spin 1s linear infinite' : 'none' }}>↻</span> Refresh
        </button>
      </div>

      {/* Body */}
      <div style={{ flex:1, display:'flex', overflow:'hidden', position:'relative' }}>

        {!loading && data && (
          <EntityPanel groups={groups} typeCounts={typeCounts} activeFilters={activeFilters} onToggleFilter={toggleFilter} meta={meta} />
        )}

        <div style={{ flex:1, position:'relative', overflow:'hidden' }}>
          {loading && (
            <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:16, background:'#030a14', zIndex:10 }}>
              <div style={{ width:42, height:42, border:'2.5px solid #131f33', borderTopColor:'#3b82f6', borderRadius:'50%', animation:'spin 1s linear infinite' }} />
              <div style={{ color:'#374151', fontSize:13 }}>Building infrastructure graph…</div>
            </div>
          )}

          {!loading && data && !data.nodes?.length && (
            <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:12 }}>
              <div style={{ fontSize:46 }}>🗺️</div>
              <div style={{ color:'#f1f5f9', fontSize:17, fontWeight:700 }}>No topology data</div>
              <div style={{ color:'#374151', fontSize:13 }}>Run a scan from the Monitoring tab first.</div>
              <button onClick={fetchData} style={{ marginTop:8, padding:'9px 20px', background:'#3b82f6', border:'none', borderRadius:8, color:'#fff', fontSize:13, fontWeight:600, cursor:'pointer' }}>Retry</button>
            </div>
          )}

          <svg ref={svgRef} width="100%" height="100%" style={{ background:'#030a14', display:'block' }} />

          {/* Zoom controls */}
          {!loading && data?.nodes?.length > 0 && (
            <div style={{ position:'absolute', bottom:58, right:16, display:'flex', flexDirection:'column', gap:4, background:'rgba(5,13,26,0.92)', borderRadius:10, border:'1px solid #131f33', padding:6 }}>
              {[{l:'+',fn:zoomIn},{l:'⊡',fn:fitAll},{l:'−',fn:zoomOut}].map(({l,fn}) => (
                <button key={l} onClick={fn} style={{ width:30, height:30, borderRadius:7, border:'1px solid #1a2a4a', background:'#070f1c', color:'#475569', cursor:'pointer', fontSize: l==='⊡'?13:18, display:'flex', alignItems:'center', justifyContent:'center' }}>{l}</button>
              ))}
            </div>
          )}

          {/* Legend */}
          {!loading && data?.nodes?.length > 0 && (
            <div style={{ position:'absolute', bottom:16, left:16, display:'flex', flexWrap:'wrap', gap:10, padding:'8px 14px', background:'rgba(5,13,26,0.92)', borderRadius:10, border:'1px solid #131f33' }}>
              {[{color:'rgba(245,158,11,0.7)',label:'Uses SG'},{color:'rgba(167,139,250,0.7)',label:'Policy Attached'},{color:'rgba(34,211,238,0.7)',label:'VPC Contains'}].map(({color,label}) => (
                <div key={label} style={{ display:'flex', alignItems:'center', gap:5 }}>
                  <div style={{ width:18, height:1.5, background:color, borderRadius:1 }} />
                  <span style={{ color:'#374151', fontSize:10 }}>{label}</span>
                </div>
              ))}
              <div style={{ width:1, background:'#131f33' }} />
              {[{color:'#ef4444',label:'Violation'},{color:'#10b981',label:'Compliant'}].map(({color,label}) => (
                <div key={label} style={{ display:'flex', alignItems:'center', gap:5 }}>
                  <div style={{ width:8, height:8, borderRadius:'50%', background:color, boxShadow:`0 0 5px ${color}` }} />
                  <span style={{ color:'#374151', fontSize:10 }}>{label}</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ position:'absolute', bottom:16, right:56, color:'#131f33', fontSize:10 }}>Scroll to zoom · Drag · Click to inspect</div>
        </div>

        <AnimatePresence>
          {selected && <Inspector node={selected} onClose={() => setSelected(null)} />}
        </AnimatePresence>
      </div>

      <style>{`
        @keyframes spin  { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
        .nd:hover .body  { stroke-width: 2.5 !important; }
      `}</style>
    </div>
  );
}

function Chip({ label, val, color, onClick, active }) {
  return (
    <div onClick={onClick} style={{ display:'flex', alignItems:'center', gap:5, padding:'4px 10px', borderRadius:16, background: active ? `${color}16` : `${color}0a`, border:`1px solid ${active ? color+'50' : color+'20'}`, cursor: onClick ? 'pointer' : 'default', transition:'all 0.15s' }}>
      <div style={{ width:5, height:5, borderRadius:'50%', background:color, boxShadow: active ? `0 0 6px ${color}` : 'none' }} />
      <span style={{ color:'#4b5563', fontSize:11 }}>{label}</span>
      <span style={{ color, fontSize:12, fontWeight:700 }}>{val}</span>
    </div>
  );
}
