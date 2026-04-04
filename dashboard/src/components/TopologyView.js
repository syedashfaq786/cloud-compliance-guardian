'use client';
import React, { useEffect, useState, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8001';

// ── Type metadata ─────────────────────────────────────────────────────────────
const TYPE_META = {
  aws_iam_user:                       { label: 'IAM User',          color: '#a78bfa', icon: '👤', group: 'Identity & Access' },
  aws_iam_role:                       { label: 'IAM Role',          color: '#c084fc', icon: '🎭', group: 'Identity & Access' },
  aws_iam_policy:                     { label: 'IAM Policy',        color: '#7c3aed', icon: '📋', group: 'Identity & Access' },
  aws_ec2_instance:                   { label: 'EC2',               color: '#34d399', icon: '🖥️', group: 'Compute' },
  aws_lambda_function:                { label: 'Lambda',            color: '#e879f9', icon: '⚡', group: 'Compute' },
  aws_ecs_cluster:                    { label: 'ECS',               color: '#4ade80', icon: '🐳', group: 'Compute' },
  aws_eks_cluster:                    { label: 'EKS',               color: '#22c55e', icon: '☸️', group: 'Compute' },
  aws_elastic_beanstalk_environment:  { label: 'Beanstalk',         color: '#86efac', icon: '🌿', group: 'Compute' },
  aws_vpc:                            { label: 'VPC',               color: '#22d3ee', icon: '🌐', group: 'Network' },
  aws_subnet:                         { label: 'Subnet',            color: '#67e8f9', icon: '🔗', group: 'Network' },
  aws_security_group:                 { label: 'Security Group',    color: '#f59e0b', icon: '🛡️', group: 'Network' },
  aws_internet_gateway:               { label: 'IGW',               color: '#38bdf8', icon: '🔌', group: 'Network' },
  aws_nat_gateway:                    { label: 'NAT GW',            color: '#0ea5e9', icon: '🔀', group: 'Network' },
  aws_route_table:                    { label: 'Route Table',       color: '#4ade80', icon: '🗺️', group: 'Network' },
  aws_eip:                            { label: 'Elastic IP',        color: '#93c5fd', icon: '📍', group: 'Network' },
  aws_lb:                             { label: 'Load Balancer',     color: '#fbbf24', icon: '⚖️', group: 'Network' },
  aws_elb:                            { label: 'Classic LB',        color: '#f59e0b', icon: '⚖️', group: 'Network' },
  aws_wafv2_web_acl:                  { label: 'WAF',               color: '#fb923c', icon: '🔰', group: 'Network' },
  aws_s3_bucket:                      { label: 'S3 Bucket',         color: '#60a5fa', icon: '🪣', group: 'Storage & Data' },
  aws_ebs_volume:                     { label: 'EBS Volume',        color: '#94a3b8', icon: '💾', group: 'Storage & Data' },
  aws_rds_instance:                   { label: 'RDS Instance',      color: '#fb923c', icon: '🗄️', group: 'Storage & Data' },
  aws_rds_cluster:                    { label: 'Aurora Cluster',    color: '#f97316', icon: '🗄️', group: 'Storage & Data' },
  aws_dynamodb_table:                 { label: 'DynamoDB',          color: '#fcd34d', icon: '📊', group: 'Storage & Data' },
  aws_elasticache_cluster:            { label: 'ElastiCache',       color: '#a3e635', icon: '⚡', group: 'Storage & Data' },
  aws_opensearch_domain:              { label: 'OpenSearch',        color: '#38bdf8', icon: '🔍', group: 'Storage & Data' },
  aws_msk_cluster:                    { label: 'MSK Kafka',         color: '#f472b6', icon: '📨', group: 'Storage & Data' },
  aws_kms_key:                        { label: 'KMS Key',           color: '#f87171', icon: '🔐', group: 'Security' },
  aws_secretsmanager_secret:          { label: 'Secret',            color: '#ef4444', icon: '🔑', group: 'Security' },
  aws_acm_certificate:                { label: 'Certificate',       color: '#fbbf24', icon: '📜', group: 'Security' },
  aws_cloudtrail:                     { label: 'CloudTrail',        color: '#818cf8', icon: '👣', group: 'Security' },
  aws_cloudwatch_alarm:               { label: 'CW Alarm',          color: '#a78bfa', icon: '🔔', group: 'Security' },
  aws_sns_topic:                      { label: 'SNS Topic',         color: '#c084fc', icon: '📣', group: 'Delivery' },
  aws_sqs_queue:                      { label: 'SQS Queue',         color: '#d8b4fe', icon: '📬', group: 'Delivery' },
  aws_api_gateway_rest_api:           { label: 'API GW (REST)',      color: '#f0abfc', icon: '🔗', group: 'Delivery' },
  aws_apigatewayv2_api:               { label: 'API GW (HTTP)',      color: '#e879f9', icon: '🔗', group: 'Delivery' },
  aws_sfn_state_machine:              { label: 'Step Functions',    color: '#86efac', icon: '⚙️', group: 'Delivery' },
  aws_cloudfront_distribution:        { label: 'CloudFront',        color: '#7dd3fc', icon: '🌍', group: 'Delivery' },
  aws_ecr_repository:                 { label: 'ECR Repo',          color: '#6ee7b7', icon: '📦', group: 'Delivery' },
};
const getMeta = (t) => TYPE_META[t] || { label: (t||'').replace('aws_','').replace(/_/g,' '), color: '#64748b', icon: '☁️', group: 'Other' };

const POSTURE_COLOR = { COMPLIANT: '#10b981', PARTIAL: '#f59e0b', 'NON-COMPLIANT': '#ef4444' };
const POSTURE_ICON  = { COMPLIANT: '✅', PARTIAL: '⚠️', 'NON-COMPLIANT': '❌' };

// ─────────────────────────────────────────────────────────────────────────────
// Inspector slide-in panel
// ─────────────────────────────────────────────────────────────────────────────
function Inspector({ node, onClose }) {
  if (!node) return null;
  const m    = getMeta(node.type);
  const comp = node.compliance || {};
  const fail = comp.status === 'fail';

  return (
    <motion.div
      initial={{ x: 400, opacity: 0 }} animate={{ x: 0, opacity: 1 }}
      exit={{ x: 400, opacity: 0 }}
      transition={{ type: 'spring', damping: 28, stiffness: 220 }}
      style={{
        position: 'absolute', top: 0, right: 0, bottom: 0, width: 380,
        background: '#07101f', borderLeft: '1px solid #1a2a4a',
        display: 'flex', flexDirection: 'column', zIndex: 80,
        boxShadow: '-20px 0 60px rgba(0,0,0,0.9)',
      }}
    >
      {/* Header */}
      <div style={{ padding: '18px 20px 14px', borderBottom: '1px solid #1a2a4a', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 42, height: 42, borderRadius: 11, background: `${m.color}15`, border: `2px solid ${m.color}40`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 19 }}>{m.icon}</div>
            <div>
              <div style={{ color: '#f1f5f9', fontSize: 13, fontWeight: 700, maxWidth: 220, wordBreak: 'break-all', lineHeight: 1.4 }}>{node.label}</div>
              <div style={{ display: 'flex', gap: 6, marginTop: 3 }}>
                <span style={{ color: m.color, fontSize: 11, fontWeight: 600 }}>{m.label}</span>
                <span style={{ color: '#2a3a56' }}>·</span>
                <span style={{ color: '#475569', fontSize: 11 }}>{node.region || 'global'}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: '#121f36', border: '1px solid #1a2a4a', color: '#475569', width: 28, height: 28, borderRadius: 8, cursor: 'pointer', fontSize: 16, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>×</button>
        </div>

        {/* Compliance badge */}
        <div style={{ padding: '9px 13px', borderRadius: 9, background: fail ? 'rgba(239,68,68,0.07)' : 'rgba(16,185,129,0.07)', border: `1px solid ${fail ? '#ef444428' : '#10b98128'}`, display: 'flex', alignItems: 'center', gap: 9 }}>
          <span style={{ fontSize: 16 }}>{fail ? '⚠️' : comp.status === 'unknown' ? '❓' : '✅'}</span>
          <div>
            <div style={{ color: fail ? '#ef4444' : comp.status === 'unknown' ? '#94a3b8' : '#10b981', fontSize: 12, fontWeight: 700 }}>
              {fail ? `${comp.failed} Check${comp.failed !== 1 ? 's' : ''} Failed` : comp.status === 'unknown' ? 'Not Evaluated' : 'Compliant'}
            </div>
            {comp.critical > 0 && <div style={{ color: '#fca5a5', fontSize: 10 }}>{comp.critical} critical/high severity</div>}
          </div>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 20px' }}>
        {/* Failed findings */}
        {comp.findings?.filter(f => f.status === 'FAIL').length > 0 && (
          <>
            <SLabel>Compliance Findings</SLabel>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
              {comp.findings.filter(f => f.status === 'FAIL').map((f, i) => (
                <div key={i} style={{ padding: '7px 10px', borderRadius: 8, background: 'rgba(239,68,68,0.06)', border: '1px solid #ef444425' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: f.severity === 'CRITICAL' ? '#ef4444' : f.severity === 'HIGH' ? '#f97316' : '#f59e0b', fontSize: 10, fontWeight: 700, flexShrink: 0 }}>{f.severity || 'MEDIUM'}</span>
                    <span style={{ color: '#94a3b8', fontSize: 11 }}>{f.rule_id}</span>
                  </div>
                  <div style={{ color: '#cbd5e1', fontSize: 11, marginTop: 3 }}>{f.title}</div>
                </div>
              ))}
            </div>
          </>
        )}

        <SLabel>Identity</SLabel>
        <SCard><KV k="ID" v={node.id} mono /><KV k="Type" v={node.type} /><KV k="Region" v={node.region || 'global'} /></SCard>

        {node.config && Object.keys(node.config).length > 0 && (
          <>
            <SLabel style={{ marginTop: 12 }}>Configuration</SLabel>
            <SCard>
              {Object.entries(node.config).filter(([,v]) => v !== '' && v !== null && v !== undefined).slice(0, 14).map(([k, v]) => (
                <KV key={k} k={k.replace(/_/g, ' ')} v={typeof v === 'object' ? JSON.stringify(v).slice(0, 70) : String(v ?? '—').slice(0, 90)} />
              ))}
            </SCard>
          </>
        )}
      </div>
    </motion.div>
  );
}

const SLabel = ({ children, style }) => <div style={{ color: '#2a3a56', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1.1px', marginBottom: 6, ...style }}>{children}</div>;
const SCard  = ({ children }) => <div style={{ background: '#060e1c', borderRadius: 8, border: '1px solid #131f33', overflow: 'hidden', marginBottom: 4 }}>{children}</div>;
const KV     = ({ k, v, mono }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '6px 11px', borderBottom: '1px solid #0c1828' }}>
    <span style={{ color: '#374151', fontSize: 11, flexShrink: 0 }}>{k}</span>
    <span style={{ color: mono ? '#7dd3fc' : '#6b7280', fontSize: 11, fontFamily: mono ? 'monospace' : 'inherit', textAlign: 'right', wordBreak: 'break-all', maxWidth: 195 }}>{v ?? '—'}</span>
  </div>
);

// ─────────────────────────────────────────────────────────────────────────────
// Resource chip — compact clickable card
// ─────────────────────────────────────────────────────────────────────────────
function ResourceChip({ node, onClick, size = 'md' }) {
  const m    = getMeta(node.type);
  const fail = node.compliance?.status === 'fail';
  const lbl  = (node.label || '').length > 20 ? node.label.slice(0, 18) + '…' : (node.label || node.id?.slice(-8));
  const pad  = size === 'sm' ? '3px 7px' : '5px 10px';
  const fs   = size === 'sm' ? 10 : 11;

  return (
    <div
      onClick={() => onClick(node)}
      title={node.label}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 5,
        padding: pad, borderRadius: 7, cursor: 'pointer',
        background: fail ? 'rgba(239,68,68,0.07)' : `${m.color}0d`,
        border: `1px solid ${fail ? '#ef444440' : m.color + '35'}`,
        transition: 'all 0.13s', position: 'relative', flexShrink: 0,
        boxShadow: fail ? '0 0 8px rgba(239,68,68,0.12)' : 'none',
      }}
      onMouseEnter={e => { e.currentTarget.style.background = fail ? 'rgba(239,68,68,0.13)' : `${m.color}1a`; e.currentTarget.style.transform = 'translateY(-1px)'; }}
      onMouseLeave={e => { e.currentTarget.style.background = fail ? 'rgba(239,68,68,0.07)' : `${m.color}0d`; e.currentTarget.style.transform = 'none'; }}
    >
      <span style={{ fontSize: fs + 2, flexShrink: 0 }}>{m.icon}</span>
      <div>
        <div style={{ color: fail ? '#fca5a5' : '#cbd5e1', fontSize: fs, fontWeight: 500, lineHeight: 1.2 }}>{lbl}</div>
        {size !== 'sm' && <div style={{ color: m.color, fontSize: 9 }}>{m.label}</div>}
      </div>
      {fail && (
        <div style={{ position: 'absolute', top: -3, right: -3, width: 8, height: 8, borderRadius: '50%', background: '#ef4444', border: '1.5px solid #07101f', boxShadow: '0 0 5px #ef4444' }} />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Subnet box inside a VPC
// ─────────────────────────────────────────────────────────────────────────────
function SubnetBox({ subnet, onClick }) {
  const isPub = subnet.is_public;
  const resources = subnet.resources || [];
  const fail = subnet.compliance?.status === 'fail';
  return (
    <div style={{
      border: `1px dashed ${isPub ? '#38bdf840' : '#6ee7b730'}`,
      borderRadius: 9, padding: '7px 9px', minWidth: 150,
      background: isPub ? 'rgba(56,189,248,0.03)' : 'rgba(110,231,183,0.02)',
      flex: '1 1 150px',
    }}>
      <div onClick={() => onClick(subnet)} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 6, cursor: 'pointer' }}>
        <span style={{ color: isPub ? '#38bdf8' : '#6ee7b7', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.7px' }}>{isPub ? '🌐 PUBLIC' : '🔒 PRIVATE'}</span>
        {subnet.az && <span style={{ color: '#1e3a5f', fontSize: 9, marginLeft: 'auto' }}>{subnet.az}</span>}
        {fail && <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 4px #ef4444', flexShrink: 0 }} />}
      </div>
      {resources.length > 0
        ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{resources.map(r => <ResourceChip key={r.id} node={r} onClick={onClick} size="sm" />)}</div>
        : <div style={{ color: '#1e2e45', fontSize: 9, textAlign: 'center', padding: '4px 0' }}>empty</div>
      }
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// VPC zone block
// ─────────────────────────────────────────────────────────────────────────────
function VpcZone({ vpc, onClick }) {
  const fail    = vpc.compliance?.status === 'fail';
  const subnets = vpc.subnets  || [];
  const unplaced = vpc.unplaced || [];
  const igws    = vpc.igws     || [];
  const sgs     = vpc.sgs      || [];
  const [collapsed, setCollapsed] = useState(subnets.length > 6);

  return (
    <div style={{
      border: `1px solid ${fail ? '#ef444440' : '#22d3ee20'}`,
      borderRadius: 12, padding: '10px 12px',
      background: 'rgba(34,211,238,0.02)',
      boxShadow: fail ? '0 0 16px rgba(239,68,68,0.07)' : 'none',
      minWidth: 280,
    }}>
      {/* VPC header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8, flexWrap: 'wrap' }}>
        <div onClick={() => onClick(vpc)} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', padding: '3px 9px', borderRadius: 7, background: fail ? 'rgba(239,68,68,0.08)' : 'rgba(34,211,238,0.08)', border: `1px solid ${fail ? '#ef444435' : '#22d3ee28'}` }}>
          <span style={{ fontSize: 13 }}>🌐</span>
          <div>
            <div style={{ color: fail ? '#ef4444' : '#22d3ee', fontSize: 11, fontWeight: 700 }}>{(vpc.label || '').length > 24 ? vpc.label.slice(0,22)+'…' : vpc.label}</div>
            {vpc.cidr && <div style={{ color: '#374151', fontSize: 9 }}>{vpc.cidr}</div>}
          </div>
          {fail && <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 4px #ef4444' }} />}
        </div>
        {vpc.internet_exposed && <span style={{ color: '#38bdf8', fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 5, background: 'rgba(56,189,248,0.1)', border: '1px solid #38bdf830' }}>🔌 INTERNET</span>}
        {igws.map(ig => (
          <div key={ig.id} onClick={() => onClick(ig)} style={{ display: 'flex', alignItems: 'center', gap: 3, cursor: 'pointer', padding: '2px 7px', borderRadius: 5, background: 'rgba(56,189,248,0.08)', border: '1px solid #38bdf825', color: '#38bdf8', fontSize: 9, fontWeight: 600 }}>
            🔌 IGW {ig.compliance?.status === 'fail' && <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} />}
          </div>
        ))}
      </div>

      {/* SGs */}
      {sgs.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '5px 7px', marginBottom: 7, borderRadius: 7, background: 'rgba(245,158,11,0.04)', border: '1px dashed #f59e0b22' }}>
          <span style={{ color: '#f59e0b', fontSize: 8, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.7px', alignSelf: 'center', marginRight: 3 }}>SGs</span>
          {sgs.map(sg => <ResourceChip key={sg.id} node={sg} onClick={onClick} size="sm" />)}
        </div>
      )}

      {/* Subnets */}
      {subnets.length > 0 && (
        <>
          <div onClick={() => setCollapsed(c => !c)} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', marginBottom: 5 }}>
            <span style={{ color: '#1e3a5f', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.7px' }}>Subnets ({subnets.length})</span>
            <span style={{ color: '#1e3a5f', fontSize: 9 }}>{collapsed ? '▶' : '▼'}</span>
          </div>
          {!collapsed && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: unplaced.length > 0 ? 7 : 0 }}>
              {subnets.map(sub => <SubnetBox key={sub.id} subnet={sub} onClick={onClick} />)}
            </div>
          )}
        </>
      )}

      {/* Unplaced */}
      {unplaced.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '5px 7px', borderRadius: 7, background: 'rgba(52,211,153,0.03)', border: '1px dashed #34d39918' }}>
          <span style={{ color: '#34d399', fontSize: 8, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.7px', alignSelf: 'center', marginRight: 3 }}>Compute</span>
          {unplaced.map(r => <ResourceChip key={r.id} node={r} onClick={onClick} size="sm" />)}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Region card
// ─────────────────────────────────────────────────────────────────────────────
function RegionCard({ region, onClick, expanded, onToggle }) {
  const hasViolations = region.violations > 0;
  const compliancePct = region.total > 0 ? Math.round(((region.total - region.violations) / region.total) * 100) : 100;

  return (
    <div style={{
      border: `1px solid ${hasViolations ? '#ef444430' : '#22d3ee18'}`,
      borderRadius: 14, overflow: 'hidden',
      background: '#050d1a',
      boxShadow: hasViolations ? '0 0 20px rgba(239,68,68,0.05)' : 'none',
    }}>
      {/* Region header — always visible */}
      <div
        onClick={onToggle}
        style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '11px 14px', cursor: 'pointer', borderBottom: expanded ? '1px solid #131f33' : 'none' }}
      >
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: hasViolations ? '#ef4444' : '#10b981', boxShadow: `0 0 6px ${hasViolations ? '#ef4444' : '#10b981'}`, flexShrink: 0 }} />
        <span style={{ color: '#f1f5f9', fontSize: 13, fontWeight: 700, flex: 1 }}>{region.name}</span>

        {/* Stats row */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ color: '#374151', fontSize: 11 }}>{region.total} resources</span>
          {region.vpcs?.length > 0 && <span style={{ color: '#22d3ee', fontSize: 11 }}>🌐 {region.vpcs.length} VPC{region.vpcs.length !== 1 ? 's' : ''}</span>}
          {hasViolations && <span style={{ color: '#ef4444', fontSize: 11, fontWeight: 700 }}>⚠ {region.violations} fail</span>}
          {region.cloudtrail
            ? <span style={{ color: '#818cf8', fontSize: 10, padding: '1px 6px', borderRadius: 5, background: 'rgba(129,140,248,0.1)', border: '1px solid #818cf825' }}>CT ✓</span>
            : <span style={{ color: '#ef4444', fontSize: 10, padding: '1px 6px', borderRadius: 5, background: 'rgba(239,68,68,0.08)', border: '1px solid #ef444425' }}>CT ✗</span>
          }
          {/* mini compliance bar */}
          <div style={{ width: 50, height: 5, borderRadius: 3, background: '#0c1828', overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${compliancePct}%`, background: compliancePct >= 80 ? '#10b981' : compliancePct >= 60 ? '#f59e0b' : '#ef4444', borderRadius: 3, transition: 'width 0.4s' }} />
          </div>
        </div>
        <span style={{ color: '#1e3a5f', fontSize: 11, marginLeft: 4 }}>{expanded ? '▲' : '▼'}</span>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div style={{ padding: '12px 14px' }}>
          {/* VPC zones */}
          {region.vpcs?.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ color: '#1e3a5f', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 8 }}>VPC Zones</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                {region.vpcs.map(vpc => <VpcZone key={vpc.id} vpc={vpc} onClick={onClick} />)}
              </div>
            </div>
          )}

          {/* Other regional resources */}
          {region.resources?.length > 0 && (
            <div>
              <div style={{ color: '#1e3a5f', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px', marginBottom: 7 }}>Regional Services ({region.resources.length})</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {region.resources.map(r => <ResourceChip key={r.id} node={r} onClick={onClick} />)}
              </div>
            </div>
          )}

          {!region.vpcs?.length && !region.resources?.length && (
            <div style={{ color: '#1e2e45', fontSize: 11, textAlign: 'center', padding: '8px 0' }}>No resources in this region</div>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence panel — grouped inventory (Config layer)
// ─────────────────────────────────────────────────────────────────────────────
function EvidencePanel({ evidence, onClick }) {
  const [openGroup, setOpenGroup] = useState(null);
  if (!evidence || Object.keys(evidence).length === 0) return <div style={{ color: '#1e2e45', fontSize: 12, padding: 20, textAlign: 'center' }}>No evidence data</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {Object.entries(evidence).map(([group, data]) => {
        const isOpen = openGroup === group;
        const vPct   = data.count > 0 ? Math.round((data.violations / data.count) * 100) : 0;
        return (
          <div key={group} style={{ border: '1px solid #131f33', borderRadius: 10, overflow: 'hidden' }}>
            <div onClick={() => setOpenGroup(isOpen ? null : group)} style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '9px 14px', cursor: 'pointer', background: '#060e1c' }}>
              <span style={{ color: '#f1f5f9', fontSize: 12, fontWeight: 600, flex: 1 }}>{group}</span>
              <span style={{ color: '#374151', fontSize: 11 }}>{data.count}</span>
              {data.violations > 0 && <span style={{ color: '#ef4444', fontSize: 11, fontWeight: 700 }}>⚠ {data.violations}</span>}
              <div style={{ width: 40, height: 4, borderRadius: 2, background: '#0c1828', overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${100 - vPct}%`, background: vPct === 0 ? '#10b981' : vPct < 30 ? '#f59e0b' : '#ef4444', transition: 'width 0.3s' }} />
              </div>
              <span style={{ color: '#1e3a5f', fontSize: 10 }}>{isOpen ? '▲' : '▼'}</span>
            </div>
            {isOpen && (
              <div style={{ padding: '10px 14px', display: 'flex', flexWrap: 'wrap', gap: 6, borderTop: '1px solid #131f33' }}>
                {data.resources.map(r => <ResourceChip key={r.id} node={r} onClick={onClick} />)}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Attribution panel — CloudTrail events
// ─────────────────────────────────────────────────────────────────────────────
function AttributionPanel({ events }) {
  if (!events?.length) return <div style={{ color: '#1e2e45', fontSize: 12, padding: 20, textAlign: 'center' }}>No CloudTrail events in cache.<br /><span style={{ fontSize: 10 }}>Run a scan to load recent activity.</span></div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {events.map((ev, i) => (
        <div key={i} style={{
          padding: '8px 12px', borderRadius: 8,
          background: ev.is_suspicious ? 'rgba(239,68,68,0.06)' : '#060e1c',
          border: `1px solid ${ev.is_suspicious ? '#ef444430' : '#131f33'}`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 3 }}>
            <span style={{ fontSize: 13 }}>{ev.is_suspicious ? '🚨' : '📝'}</span>
            <span style={{ color: ev.is_suspicious ? '#ef4444' : '#94a3b8', fontSize: 12, fontWeight: 600, flex: 1 }}>{ev.event_name}</span>
            <span style={{ color: '#1e3a5f', fontSize: 10 }}>{ev.region}</span>
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ color: '#475569', fontSize: 10 }}>👤 {ev.username}</span>
            <span style={{ color: '#475569', fontSize: 10 }}>📡 {ev.event_source?.replace('.amazonaws.com', '')}</span>
            {ev.source_ip && <span style={{ color: '#475569', fontSize: 10 }}>🌐 {ev.source_ip}</span>}
            {ev.error_code && <span style={{ color: '#ef4444', fontSize: 10 }}>✗ {ev.error_code}</span>}
          </div>
          {ev.event_time && <div style={{ color: '#1e3a5f', fontSize: 9, marginTop: 2 }}>{new Date(ev.event_time).toLocaleString()}</div>}
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Org header — top banner
// ─────────────────────────────────────────────────────────────────────────────
function OrgHeader({ org }) {
  if (!org || !org.scan_time) return null;
  const pc = POSTURE_COLOR[org.posture] || '#94a3b8';
  const pi = POSTURE_ICON[org.posture]  || '❓';

  return (
    <div style={{
      display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 12,
      padding: '12px 20px', borderRadius: 12, marginBottom: 18,
      background: 'linear-gradient(135deg, #060f1f 0%, #0a1628 100%)',
      border: `1px solid ${pc}30`,
      boxShadow: `0 0 30px ${pc}10`,
    }}>
      {/* AWS Org block */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ width: 42, height: 42, borderRadius: 10, background: `${pc}15`, border: `2px solid ${pc}40`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 20 }}>🏢</div>
        <div>
          <div style={{ color: '#f1f5f9', fontSize: 13, fontWeight: 700 }}>AWS Account</div>
          <div style={{ color: '#374151', fontSize: 11 }}>{org.account_id || 'Account'} · {org.primary_region}</div>
        </div>
      </div>

      <div style={{ width: 1, height: 36, background: '#131f33' }} />

      {/* Posture */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 18 }}>{pi}</span>
        <div>
          <div style={{ color: pc, fontSize: 13, fontWeight: 800 }}>{org.posture}</div>
          <div style={{ color: '#374151', fontSize: 10 }}>Compliance Posture</div>
        </div>
        {/* score ring */}
        <div style={{ position: 'relative', width: 44, height: 44 }}>
          <svg viewBox="0 0 44 44" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="22" cy="22" r="18" fill="none" stroke="#0c1828" strokeWidth="4" />
            <circle cx="22" cy="22" r="18" fill="none" stroke={pc} strokeWidth="4"
              strokeDasharray={`${(org.score / 100) * 113} 113`} strokeLinecap="round" />
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: pc, fontSize: 11, fontWeight: 800 }}>{org.score}%</div>
        </div>
      </div>

      <div style={{ width: 1, height: 36, background: '#131f33' }} />

      {/* Stats */}
      {[
        { label: 'Regions',    val: org.regions_active, icon: '🗺️', color: '#22d3ee' },
        { label: 'Resources',  val: org.total_resources, icon: '☁️', color: '#60a5fa' },
        { label: 'Compliant',  val: org.compliant, icon: '✅', color: '#10b981' },
        { label: 'Violations', val: org.violations, icon: '⚠️', color: '#ef4444' },
      ].map(({ label, val, icon, color }) => (
        <div key={label} style={{ textAlign: 'center', minWidth: 52 }}>
          <div style={{ color, fontSize: 18, fontWeight: 800, lineHeight: 1 }}>{val ?? 0}</div>
          <div style={{ color: '#374151', fontSize: 10 }}>{label}</div>
        </div>
      ))}

      <div style={{ width: 1, height: 36, background: '#131f33' }} />

      {/* CloudTrail status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <span style={{ fontSize: 15 }}>👣</span>
        <div>
          <div style={{ color: org.cloudtrail_enabled ? '#818cf8' : '#ef4444', fontSize: 12, fontWeight: 700 }}>CloudTrail {org.cloudtrail_enabled ? `✓ (${org.cloudtrail_count} trail${org.cloudtrail_count !== 1 ? 's' : ''})` : '✗ MISSING'}</div>
          <div style={{ color: '#374151', fontSize: 10 }}>{org.config_rules_checked} checks evaluated</div>
        </div>
      </div>

      <div style={{ flex: 1 }} />
      <div style={{ color: '#1e3a5f', fontSize: 10, textAlign: 'right' }}>
        Last scan<br />{org.scan_time ? new Date(org.scan_time).toLocaleString() : '—'}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Left sidebar
// ─────────────────────────────────────────────────────────────────────────────
function Sidebar({ typeCounts, meta, activeTab, onTabChange }) {
  const tabs = [
    { id: 'regions',     label: 'Regions',     icon: '🗺️' },
    { id: 'evidence',    label: 'Inventory',   icon: '📋' },
    { id: 'attribution', label: 'Activity',    icon: '👣' },
    { id: 'global',      label: 'Global',      icon: '🌍' },
  ];

  // type count summary
  const grouped = {};
  Object.entries(typeCounts).forEach(([t, c]) => {
    const g = getMeta(t).group || 'Other';
    grouped[g] = (grouped[g] || 0) + c;
  });

  return (
    <div style={{ width: 210, flexShrink: 0, background: '#050d1a', borderRight: '1px solid #131f33', display: 'flex', flexDirection: 'column' }}>
      {/* Stats */}
      <div style={{ padding: '14px 14px 10px', borderBottom: '1px solid #131f33' }}>
        <div style={{ color: '#2a3a56', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 4 }}>Total Resources</div>
        <div style={{ color: '#f1f5f9', fontSize: 26, fontWeight: 800, lineHeight: 1 }}>{meta.total || 0}</div>
        <div style={{ display: 'flex', gap: 12, marginTop: 7 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 4px #10b981' }} />
            <span style={{ color: '#10b981', fontSize: 11, fontWeight: 600 }}>{meta.compliant}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#ef4444', boxShadow: '0 0 4px #ef4444' }} />
            <span style={{ color: '#ef4444', fontSize: 11, fontWeight: 600 }}>{meta.violations}</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', flexDirection: 'column', padding: '6px 8px', gap: 3, borderBottom: '1px solid #131f33' }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => onTabChange(t.id)} style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px', borderRadius: 8, border: 'none', cursor: 'pointer', textAlign: 'left',
            background: activeTab === t.id ? 'rgba(59,130,246,0.12)' : 'transparent',
            color: activeTab === t.id ? '#60a5fa' : '#4b5563',
          }}>
            <span style={{ fontSize: 14 }}>{t.icon}</span>
            <span style={{ fontSize: 12, fontWeight: activeTab === t.id ? 700 : 400 }}>{t.label}</span>
          </button>
        ))}
      </div>

      {/* Resource type counts */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
        {Object.entries(grouped).sort(([,a],[,b]) => b - a).map(([g, c]) => (
          <div key={g} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 14px' }}>
            <span style={{ color: '#4b5563', fontSize: 11, flex: 1 }}>{g}</span>
            <span style={{ color: '#374151', fontSize: 12, fontWeight: 700 }}>{c}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────────
export default function TopologyView() {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState(null);
  const [activeTab, setActiveTab] = useState('regions');
  const [lastSync, setLastSync] = useState(null);
  const [expandedRegions, setExpandedRegions] = useState({});
  const [search, setSearch]     = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}/api/topology`);
      const j = await r.json();
      setData(j);
      setLastSync(new Date());
      // Auto-expand regions with violations first
      const init = {};
      (j.regions || []).forEach((reg, i) => {
        init[reg.name] = i < 2 || reg.violations > 0;
      });
      setExpandedRegions(init);
    } catch {}
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    fetchData();
    let ws;
    try {
      ws = new WebSocket(`${API.replace('http', 'ws')}/api/ws/topology`);
      ws.onmessage = ev => { try { if (JSON.parse(ev.data).type === 'RESOURCE_UPDATED') fetchData(); } catch {} };
    } catch {}
    return () => ws?.close();
  }, [fetchData]);

  const handleClick = useCallback((node) => setSelected(p => p?.id === node.id ? null : node), []);
  const toggleRegion = useCallback((name) => setExpandedRegions(p => ({ ...p, [name]: !p[name] })), []);

  const meta        = data?.meta        || {};
  const typeCounts  = data?.type_counts || {};
  const orgLayer    = data?.org_layer   || {};
  const regions     = data?.regions     || [];
  const attribution = data?.attribution || [];
  const evidence    = data?.evidence    || {};
  const globalRes   = data?.global_resources || [];

  // Filter regions/resources by search
  const filterNode = (n) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (n.label||'').toLowerCase().includes(q) || (n.type||'').toLowerCase().includes(q) || (n.id||'').toLowerCase().includes(q);
  };

  const filteredRegions = search ? regions.map(reg => ({
    ...reg,
    vpcs: (reg.vpcs || []).map(vpc => ({
      ...vpc,
      subnets: (vpc.subnets || []).map(s => ({ ...s, resources: (s.resources || []).filter(filterNode) })),
      unplaced: (vpc.unplaced || []).filter(filterNode),
      sgs: (vpc.sgs || []).filter(filterNode),
    })),
    resources: (reg.resources || []).filter(filterNode),
  })) : regions;

  const isEmpty = !loading && !data?.org_layer?.scan_time && (regions.length === 0);

  return (
    <div style={{ width: '100%', height: 'calc(100vh - 60px)', display: 'flex', flexDirection: 'column', background: '#030a14', fontFamily: 'inherit' }}>

      {/* Top bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 18px', borderBottom: '1px solid #131f33', flexShrink: 0, background: '#050d1a' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 7px #10b981', animation: 'pulse 2s infinite' }} />
          <span style={{ color: '#f1f5f9', fontSize: 14, fontWeight: 700 }}>Audit Topology</span>
          {lastSync && <span style={{ color: '#1e2e45', fontSize: 11 }}>· {lastSync.toLocaleTimeString()}</span>}
        </div>

        {meta.total > 0 && (
          <div style={{ display: 'flex', gap: 6, marginLeft: 6 }}>
            {[
              { l: 'Resources', v: meta.total,      c: '#3b82f6' },
              { l: 'Compliant', v: meta.compliant,  c: '#10b981' },
              { l: 'Violations',v: meta.violations, c: '#ef4444' },
              { l: 'Score',     v: meta.score != null ? `${meta.score}%` : '—', c: POSTURE_COLOR[meta.posture] || '#94a3b8' },
            ].map(({ l, v, c }) => (
              <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '3px 9px', borderRadius: 14, background: `${c}0a`, border: `1px solid ${c}20` }}>
                <div style={{ width: 4, height: 4, borderRadius: '50%', background: c }} />
                <span style={{ color: '#4b5563', fontSize: 10 }}>{l}</span>
                <span style={{ color: c, fontSize: 11, fontWeight: 700 }}>{v}</span>
              </div>
            ))}
          </div>
        )}

        <div style={{ flex: 1 }} />

        <div style={{ position: 'relative' }}>
          <span style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', color: '#1e2e45', fontSize: 11 }}>🔍</span>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search resources…"
            style={{ background: '#090f1e', border: '1px solid #131f33', borderRadius: 7, color: '#cbd5e1', fontSize: 11, padding: '5px 8px 5px 24px', width: 180, outline: 'none' }} />
        </div>

        <button onClick={fetchData} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '5px 11px', background: '#090f1e', border: '1px solid #131f33', borderRadius: 7, color: '#475569', fontSize: 11, cursor: 'pointer' }}>
          <span style={{ display: 'inline-block', animation: loading ? 'spin 1s linear infinite' : 'none' }}>↻</span> Refresh
        </button>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative' }}>

        {/* Sidebar */}
        {!loading && data && (
          <Sidebar typeCounts={typeCounts} meta={meta} activeTab={activeTab} onTabChange={setActiveTab} />
        )}

        {/* Canvas */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '18px 22px', position: 'relative' }}>

          {loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, background: '#030a14', zIndex: 10 }}>
              <div style={{ width: 44, height: 44, border: '2.5px solid #131f33', borderTopColor: '#3b82f6', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
              <div style={{ color: '#374151', fontSize: 13 }}>Building audit topology…</div>
            </div>
          )}

          {isEmpty && !loading && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
              <div style={{ fontSize: 48 }}>🗺️</div>
              <div style={{ color: '#f1f5f9', fontSize: 17, fontWeight: 700 }}>No topology data</div>
              <div style={{ color: '#374151', fontSize: 13 }}>Run a scan from the Monitoring tab first.</div>
              <button onClick={fetchData} style={{ marginTop: 8, padding: '9px 20px', background: '#3b82f6', border: 'none', borderRadius: 8, color: '#fff', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}>Retry</button>
            </div>
          )}

          {!loading && data && !isEmpty && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 0, maxWidth: 1400 }}>

              {/* ── Org Header (always) ── */}
              <OrgHeader org={orgLayer} />

              {/* ── REGIONS TAB ── */}
              {activeTab === 'regions' && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <div style={{ width: 3, height: 16, borderRadius: 2, background: '#22d3ee' }} />
                    <span style={{ color: '#22d3ee', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px' }}>Resource Topology</span>
                    <span style={{ color: '#1e3a5f', fontSize: 11 }}>— Account → Region → VPC → Resource</span>
                    <div style={{ flex: 1 }} />
                    <button onClick={() => setExpandedRegions(Object.fromEntries(filteredRegions.map(r => [r.name, true])))} style={{ padding: '3px 9px', background: '#090f1e', border: '1px solid #131f33', borderRadius: 6, color: '#4b5563', fontSize: 10, cursor: 'pointer' }}>Expand All</button>
                    <button onClick={() => setExpandedRegions({})} style={{ padding: '3px 9px', background: '#090f1e', border: '1px solid #131f33', borderRadius: 6, color: '#4b5563', fontSize: 10, cursor: 'pointer' }}>Collapse All</button>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {filteredRegions.length === 0
                      ? <div style={{ color: '#1e2e45', fontSize: 12, textAlign: 'center', padding: 20 }}>No regions found</div>
                      : filteredRegions.map(reg => (
                          <RegionCard key={reg.name} region={reg} onClick={handleClick}
                            expanded={!!expandedRegions[reg.name]} onToggle={() => toggleRegion(reg.name)} />
                        ))
                    }
                  </div>
                </div>
              )}

              {/* ── EVIDENCE TAB ── */}
              {activeTab === 'evidence' && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <div style={{ width: 3, height: 16, borderRadius: 2, background: '#60a5fa' }} />
                    <span style={{ color: '#60a5fa', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px' }}>Resource Inventory</span>
                    <span style={{ color: '#1e3a5f', fontSize: 11 }}>— Service-grouped evidence for auditors</span>
                  </div>
                  <EvidencePanel evidence={evidence} onClick={handleClick} />
                </div>
              )}

              {/* ── ATTRIBUTION TAB ── */}
              {activeTab === 'attribution' && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <div style={{ width: 3, height: 16, borderRadius: 2, background: '#818cf8' }} />
                    <span style={{ color: '#818cf8', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px' }}>CloudTrail Activity</span>
                    <span style={{ color: '#1e3a5f', fontSize: 11 }}>— Who did what and when</span>
                  </div>
                  <AttributionPanel events={attribution} />
                </div>
              )}

              {/* ── GLOBAL TAB ── */}
              {activeTab === 'global' && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <div style={{ width: 3, height: 16, borderRadius: 2, background: '#7dd3fc' }} />
                    <span style={{ color: '#7dd3fc', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.8px' }}>Global Resources</span>
                    <span style={{ color: '#1e3a5f', fontSize: 11 }}>— IAM, S3, CloudFront (not region-bound)</span>
                  </div>
                  {globalRes.length > 0
                    ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                        {globalRes.filter(filterNode).map(r => <ResourceChip key={r.id} node={r} onClick={handleClick} />)}
                      </div>
                    : <div style={{ color: '#1e2e45', fontSize: 12, textAlign: 'center', padding: 20 }}>No global resources found</div>
                  }
                </div>
              )}

            </div>
          )}
        </div>

        {/* Inspector */}
        <AnimatePresence>
          {selected && <Inspector node={selected} onClose={() => setSelected(null)} />}
        </AnimatePresence>
      </div>

      <style>{`
        @keyframes spin  { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      `}</style>
    </div>
  );
}
