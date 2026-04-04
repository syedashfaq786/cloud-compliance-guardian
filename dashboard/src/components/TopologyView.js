"use client";
import { useState, useEffect, useCallback, useMemo } from "react";
import ReactFlow, {
  Controls, Background, MiniMap, useNodesState, useEdgesState,
  MarkerType, Handle, Position,
} from "reactflow";
import "reactflow/dist/style.css";
import dagre from "dagre";
import { AnimatePresence, motion } from "framer-motion";

const API = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

// ─── Compliance Colors ───────────────────────────────────────────────────────
const C = {
  pass:    { border: "#22c55e", bg: "#052e16", badge: "#22c55e", text: "PASS" },
  fail:    { border: "#ef4444", bg: "#2d0a0a", badge: "#ef4444", text: "FAIL" },
  warn:    { border: "#f59e0b", bg: "#2d1b00", badge: "#f59e0b", text: "WARN" },
  unknown: { border: "#334155", bg: "#0f172a", badge: "#475569", text: "—"    },
};
const cs = (compliance) => {
  const s = (compliance?.status || "unknown").toLowerCase();
  return C[s] || C.unknown;
};

// ─── Type metadata ───────────────────────────────────────────────────────────
const TM = {
  account:                    { icon: "🔑", label: "Account",        color: "#60a5fa" },
  region:                     { icon: "🌍", label: "Region",         color: "#34d399" },
  iam_group:                  { icon: "👥", label: "IAM",            color: "#c084fc" },
  global_group:               { icon: "🌐", label: "Global",         color: "#22d3ee" },
  aws_vpc:                    { icon: "🔷", label: "VPC",            color: "#06b6d4" },
  aws_subnet:                 { icon: "📦", label: "Subnet",         color: "#0ea5e9" },
  aws_security_group:         { icon: "🛡️", label: "Security Group", color: "#fb923c" },
  aws_internet_gateway:       { icon: "🌐", label: "IGW",            color: "#38bdf8" },
  aws_ec2_instance:           { icon: "💻", label: "EC2",            color: "#34d399" },
  aws_lambda_function:        { icon: "⚡", label: "Lambda",         color: "#a3e635" },
  aws_s3_bucket:              { icon: "🪣", label: "S3 Bucket",      color: "#60a5fa" },
  aws_rds_instance:           { icon: "🗄️", label: "RDS",            color: "#f472b6" },
  aws_rds_cluster:            { icon: "🗄️", label: "RDS Cluster",    color: "#f472b6" },
  aws_dynamodb_table:         { icon: "📊", label: "DynamoDB",       color: "#fb923c" },
  aws_iam_user:               { icon: "👤", label: "IAM User",       color: "#c084fc" },
  aws_iam_role:               { icon: "🎭", label: "IAM Role",       color: "#a78bfa" },
  aws_iam_policy:             { icon: "📋", label: "Policy",         color: "#818cf8" },
  aws_kms_key:                { icon: "🔐", label: "KMS Key",        color: "#fb923c" },
  aws_cloudtrail:             { icon: "📝", label: "CloudTrail",     color: "#fbbf24" },
  aws_cloudwatch_alarm:       { icon: "🔔", label: "CloudWatch",     color: "#f59e0b" },
  aws_secretsmanager_secret:  { icon: "🔒", label: "Secret",         color: "#f87171" },
  aws_eks_cluster:            { icon: "☸️", label: "EKS",            color: "#38bdf8" },
  aws_ecs_cluster:            { icon: "🐳", label: "ECS",            color: "#0ea5e9" },
  aws_elb:                    { icon: "⚖️", label: "Load Balancer",  color: "#22d3ee" },
  aws_lb:                     { icon: "⚖️", label: "Load Balancer",  color: "#22d3ee" },
  aws_acm_certificate:        { icon: "📜", label: "Certificate",    color: "#a3e635" },
  aws_sqs_queue:              { icon: "📨", label: "SQS",            color: "#f59e0b" },
  aws_sns_topic:              { icon: "📣", label: "SNS",            color: "#fb923c" },
  aws_ebs_volume:             { icon: "💾", label: "EBS Volume",     color: "#60a5fa" },
  aws_cloudfront_distribution:{ icon: "🚀", label: "CloudFront",     color: "#f472b6" },
  default:                    { icon: "⬡",  label: "Resource",       color: "#94a3b8" },
};
const tm = (type) => TM[type] || TM.default;

// ─── Dagre auto-layout ───────────────────────────────────────────────────────
function layout(nodes, edges, dir = "TB") {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: dir, ranksep: 90, nodesep: 55, marginx: 40, marginy: 40 });
  nodes.forEach((n) => g.setNode(n.id, { width: n.width || 180, height: n.height || 65 }));
  edges.forEach((e) => g.setEdge(e.source, e.target));
  dagre.layout(g);
  return nodes.map((n) => {
    const p = g.node(n.id);
    return { ...n, position: { x: p.x - (n.width || 180) / 2, y: p.y - (n.height || 65) / 2 } };
  });
}

// ─── Shared edge factory ─────────────────────────────────────────────────────
const edge = (id, source, target, color = "#1e293b", label = "", dashed = false) => ({
  id, source, target, type: "smoothstep",
  label, labelStyle: { fill: "#475569", fontSize: 9 },
  style: { stroke: color, strokeWidth: 1.5, strokeDasharray: dashed ? "4 2" : undefined },
  markerEnd: { type: MarkerType.ArrowClosed, color },
});

// ─── Custom Node: Account Root ───────────────────────────────────────────────
function AccountNode({ data }) {
  const score = data.score || 0;
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : "#ef4444";
  const posture = data.posture || "UNKNOWN";
  const borderColor = posture === "COMPLIANT" ? "#22c55e" : posture === "PARTIAL" ? "#f59e0b" : "#ef4444";
  return (
    <div style={{ background: "#07101f", border: `2px solid ${borderColor}`, borderRadius: 12, padding: "14px 18px", minWidth: 220, cursor: "pointer", boxShadow: `0 0 24px ${borderColor}25` }}>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
        <span style={{ fontSize: 24 }}>🔑</span>
        <div style={{ flex: 1 }}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 13 }}>AWS Account</div>
          <div style={{ color: "#94a3b8", fontSize: 10, fontFamily: "monospace" }}>{data.account_id || "—"}</div>
        </div>
        <span style={{ background: borderColor, color: "#000", borderRadius: 5, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>{posture}</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 5 }}>
        {[
          { label: "Resources", val: data.total_resources || 0, c: "#60a5fa" },
          { label: "Violations", val: data.violations || 0, c: (data.violations || 0) > 0 ? "#ef4444" : "#22c55e" },
          { label: "Score", val: `${score}%`, c: color },
        ].map(({ label, val, c }) => (
          <div key={label} style={{ background: "#0c1828", borderRadius: 7, padding: "5px 6px", textAlign: "center" }}>
            <div style={{ color: c, fontSize: 13, fontWeight: 700 }}>{val}</div>
            <div style={{ color: "#475569", fontSize: 9 }}>{label}</div>
          </div>
        ))}
      </div>
      {data.cloudtrail_enabled != null && (
        <div style={{ marginTop: 8, display: "flex", gap: 6 }}>
          <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: data.cloudtrail_enabled ? "#052e16" : "#2d0a0a", color: data.cloudtrail_enabled ? "#22c55e" : "#ef4444" }}>
            {data.cloudtrail_enabled ? "✓ CloudTrail" : "✗ CloudTrail"}
          </span>
          {data.regions_active > 0 && (
            <span style={{ fontSize: 9, padding: "2px 6px", borderRadius: 3, background: "#0c1828", color: "#34d399" }}>
              {data.regions_active} regions
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Custom Node: Group (Region / IAM / Global / VPC) ───────────────────────
function GroupNode({ data }) {
  const meta = tm(data.nodeType || "default");
  const isActive = data.active;
  return (
    <div style={{ background: "#07101f", border: `2px solid ${isActive ? meta.color : "#1e293b"}`, borderRadius: 10, padding: "9px 14px", minWidth: 165, cursor: "pointer", transition: "all 0.2s", boxShadow: isActive ? `0 0 14px ${meta.color}35` : "none" }}>
      <Handle type="target" position={Position.Top}    style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 18 }}>{meta.icon}</span>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 12, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{data.label}</div>
          {data.subtitle && <div style={{ color: "#475569", fontSize: 9 }}>{data.subtitle}</div>}
        </div>
        {(data.violations || 0) > 0 && (
          <span style={{ background: "#ef444418", color: "#ef4444", borderRadius: 4, padding: "1px 5px", fontSize: 9, fontWeight: 700 }}>⚠ {data.violations}</span>
        )}
        {data.count != null && (
          <span style={{ background: "#131f33", color: "#94a3b8", borderRadius: 4, padding: "1px 5px", fontSize: 9 }}>{data.count}</span>
        )}
        <span style={{ color: isActive ? meta.color : "#334155", fontSize: 11 }}>▸</span>
      </div>
      {data.badges?.length > 0 && (
        <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
          {data.badges.map((b, i) => (
            <span key={i} style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: b.bg, color: b.color }}>{b.text}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Custom Node: Leaf Resource ──────────────────────────────────────────────
function ResourceNode({ data }) {
  const meta = tm(data.type);
  const style = cs(data.compliance);
  return (
    <div style={{ background: style.bg, border: `1.5px solid ${style.border}`, borderRadius: 8, padding: "7px 10px", minWidth: 155, maxWidth: 185, cursor: "pointer" }}>
      <Handle type="target" position={Position.Top}    style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: 14 }}>{meta.icon}</span>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <div style={{ color: "#f1f5f9", fontWeight: 600, fontSize: 11, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{data.label}</div>
          <div style={{ color: "#94a3b8", fontSize: 9 }}>{meta.label}</div>
        </div>
        <span style={{ background: style.badge, color: "#000", borderRadius: 3, padding: "1px 5px", fontSize: 8, fontWeight: 700, flexShrink: 0 }}>{style.text}</span>
      </div>
      {data.compliance?.findings?.[0] && (
        <div style={{ marginTop: 4, color: "#f87171", fontSize: 9, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          ⚠ {data.compliance.findings[0].title}
        </div>
      )}
    </div>
  );
}

// ─── Custom Node: VPC ────────────────────────────────────────────────────────
function VpcNode({ data }) {
  const style = cs(data.compliance);
  const exposed = data.internet_exposed;
  return (
    <div style={{ background: "#060d1c", border: `2px solid ${exposed ? "#ef4444" : "#0ea5e9"}`, borderRadius: 10, padding: "9px 14px", minWidth: 175, cursor: "pointer" }}>
      <Handle type="target" position={Position.Top}    style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 16 }}>🔷</span>
        <div style={{ flex: 1, overflow: "hidden" }}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 12, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{data.label}</div>
          <div style={{ color: "#475569", fontSize: 9, fontFamily: "monospace" }}>{data.cidr}</div>
        </div>
        {exposed
          ? <span style={{ background: "#ef444420", color: "#ef4444", fontSize: 9, borderRadius: 3, padding: "1px 5px", fontWeight: 700 }}>PUBLIC</span>
          : <span style={{ background: "#052e1650", color: "#22c55e", fontSize: 9, borderRadius: 3, padding: "1px 5px" }}>PRIVATE</span>
        }
      </div>
      <div style={{ display: "flex", gap: 4, marginTop: 6 }}>
        {data.subnet_count > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: "#0c1828", color: "#94a3b8" }}>{data.subnet_count} subnets</span>}
        {data.sg_count > 0 && <span style={{ fontSize: 8, padding: "1px 5px", borderRadius: 3, background: "#fb923c18", color: "#fb923c" }}>{data.sg_count} SGs</span>}
      </div>
    </div>
  );
}

const nodeTypes = { accountNode: AccountNode, groupNode: GroupNode, resourceNode: ResourceNode, vpcNode: VpcNode };

// ─── Graph builders ──────────────────────────────────────────────────────────

function buildOverviewGraph(data, currentView) {
  const nodes = [], edges_ = [];
  const accId = "account-root";
  const ol = data.org_layer || {};

  nodes.push({
    id: accId, type: "accountNode", width: 240, height: 120,
    data: {
      account_id: ol.account_id, posture: ol.posture, score: ol.score,
      total_resources: ol.total_resources, violations: ol.violations,
      cloudtrail_enabled: ol.cloudtrail_enabled, regions_active: ol.regions_active,
    },
    position: { x: 0, y: 0 },
  });

  // IAM group
  const iam = data.evidence?.["Identity & Access"] || {};
  nodes.push({
    id: "g-iam", type: "groupNode", width: 175, height: 65,
    data: {
      label: "Identity & Access", nodeType: "iam_group",
      subtitle: `${iam.count || 0} principals`, count: iam.count || 0,
      violations: iam.violations || 0, active: currentView === "iam",
      badges: iam.violations > 0 ? [{ text: "Has Violations", bg: "#2d0a0a", color: "#ef4444" }] : [],
    },
    position: { x: 0, y: 0 },
  });
  edges_.push(edge("e-acc-iam", accId, "g-iam", "#c084fc"));

  // Region groups
  (data.regions || []).forEach((r, i) => {
    const id = `g-reg-${r.name}`;
    nodes.push({
      id, type: "groupNode", width: 175, height: 65,
      data: {
        label: r.name, nodeType: "region",
        subtitle: `${r.total || 0} resources · ${r.vpcs?.length || 0} VPCs`,
        count: r.total || 0, violations: r.violations || 0,
        active: currentView === `region:${r.name}`,
        badges: [
          r.cloudtrail
            ? { text: "✓ CloudTrail", bg: "#052e16", color: "#22c55e" }
            : { text: "✗ CloudTrail", bg: "#2d0a0a", color: "#ef4444" },
        ],
      },
      position: { x: 0, y: 0 },
    });
    edges_.push(edge(`e-acc-reg-${i}`, accId, id, "#34d399"));
  });

  // Global group
  const gCount = data.global_resources?.length || 0;
  if (gCount > 0) {
    const gViolations = (data.global_resources || []).filter(r => r.compliance?.status === "fail").length;
    nodes.push({
      id: "g-global", type: "groupNode", width: 175, height: 65,
      data: {
        label: "Global Resources", nodeType: "global_group",
        subtitle: "S3, IAM, CloudFront", count: gCount, violations: gViolations,
        active: currentView === "global",
      },
      position: { x: 0, y: 0 },
    });
    edges_.push(edge("e-acc-global", accId, "g-global", "#22d3ee"));
  }

  return { nodes: layout(nodes, edges_, "TB"), edges: edges_ };
}

function buildIAMGraph(evidence) {
  const nodes = [], edges_ = [];
  const resources = evidence?.["Identity & Access"]?.resources || [];
  const users    = resources.filter(r => r.type === "aws_iam_user");
  const roles    = resources.filter(r => r.type === "aws_iam_role");
  const policies = resources.filter(r => r.type === "aws_iam_policy");

  const addGroup = (id, label, count, violations) => {
    nodes.push({ id, type: "groupNode", width: 165, height: 55, data: { label, nodeType: "iam_group", count, violations, active: true }, position: { x: 0, y: 0 } });
  };

  if (users.length) {
    addGroup("h-users", "IAM Users", users.length, users.filter(u => u.compliance?.status === "fail").length);
    users.forEach((u, i) => {
      const id = `iam-u-${i}`;
      nodes.push({ id, type: "resourceNode", width: 175, height: 65, data: { ...u }, position: { x: 0, y: 0 } });
      edges_.push(edge(`e-uh-${i}`, "h-users", id, "#c084fc50"));
    });
  }
  if (roles.length) {
    addGroup("h-roles", "IAM Roles", roles.length, roles.filter(r => r.compliance?.status === "fail").length);
    roles.forEach((r, i) => {
      const id = `iam-r-${i}`;
      nodes.push({ id, type: "resourceNode", width: 175, height: 65, data: { ...r }, position: { x: 0, y: 0 } });
      edges_.push(edge(`e-rh-${i}`, "h-roles", id, "#a78bfa50"));
    });
  }
  if (policies.length) {
    addGroup("h-pols", "IAM Policies", policies.length, policies.filter(p => p.compliance?.status === "fail").length);
    policies.slice(0, 20).forEach((p, i) => {
      const id = `iam-p-${i}`;
      nodes.push({ id, type: "resourceNode", width: 175, height: 65, data: { ...p }, position: { x: 0, y: 0 } });
      edges_.push(edge(`e-ph-${i}`, "h-pols", id, "#818cf850"));
    });
  }

  if (users.length && roles.length)   edges_.push(edge("e-u-r",   "h-users", "h-roles", "#475569", "assumes", true));
  if (roles.length && policies.length) edges_.push(edge("e-r-p", "h-roles", "h-pols", "#475569", "has policy", true));

  return { nodes: layout(nodes, edges_, "LR"), edges: edges_ };
}

function buildRegionGraph(region) {
  if (!region) return { nodes: [], edges: [] };
  const nodes = [], edges_ = [];
  const regId = `reg-${region.name}`;

  nodes.push({
    id: regId, type: "groupNode", width: 185, height: 65,
    data: {
      label: region.name, nodeType: "region", active: true,
      subtitle: `${region.total} resources · ${region.vpcs?.length || 0} VPCs`,
      count: region.total, violations: region.violations,
      badges: [region.cloudtrail
        ? { text: "✓ CloudTrail", bg: "#052e16", color: "#22c55e" }
        : { text: "✗ CloudTrail", bg: "#2d0a0a", color: "#ef4444" }],
    },
    position: { x: 0, y: 0 },
  });

  (region.vpcs || []).forEach((vpc, vi) => {
    const vpcId = `vpc-${vi}`;
    nodes.push({
      id: vpcId, type: "vpcNode", width: 185, height: 80,
      data: {
        label: vpc.label || vpc.id, cidr: vpc.cidr,
        internet_exposed: vpc.internet_exposed, compliance: vpc.compliance,
        subnet_count: vpc.subnets?.length || 0, sg_count: vpc.sgs?.length || 0,
      },
      position: { x: 0, y: 0 },
    });
    edges_.push(edge(`e-rv-${vi}`, regId, vpcId, "#06b6d440"));

    (vpc.subnets || []).forEach((sub, si) => {
      const subId = `sub-${vi}-${si}`;
      nodes.push({
        id: subId, type: "groupNode", width: 175, height: 60,
        data: {
          label: sub.is_public ? "🔓 Public Subnet" : "🔒 Private Subnet",
          nodeType: "aws_subnet", subtitle: `${sub.az} · ${sub.resources?.length || 0} res`,
          count: sub.resources?.length || 0,
          violations: (sub.resources || []).filter(r => r.compliance?.status === "fail").length,
          active: true,
        },
        position: { x: 0, y: 0 },
      });
      edges_.push(edge(`e-vs-${vi}-${si}`, vpcId, subId, "#0ea5e930"));

      (sub.resources || []).slice(0, 8).forEach((r, ri) => {
        const rId = `sres-${vi}-${si}-${ri}`;
        nodes.push({ id: rId, type: "resourceNode", width: 175, height: 65, data: { ...r }, position: { x: 0, y: 0 } });
        edges_.push(edge(`e-sr-${rId}`, subId, rId, "#1e293b"));
      });
    });

    (vpc.sgs || []).slice(0, 6).forEach((sg, si) => {
      const sgId = `sg-${vi}-${si}`;
      nodes.push({ id: sgId, type: "resourceNode", width: 175, height: 65, data: { ...sg }, position: { x: 0, y: 0 } });
      edges_.push(edge(`e-vsg-${vi}-${si}`, vpcId, sgId, "#fb923c30"));
    });

    (vpc.igws || []).forEach((igw, ii) => {
      const igwId = `igw-${vi}-${ii}`;
      nodes.push({ id: igwId, type: "resourceNode", width: 175, height: 65, data: { ...igw }, position: { x: 0, y: 0 } });
      edges_.push(edge(`e-vigw-${vi}-${ii}`, vpcId, igwId, "#38bdf830"));
    });
  });

  (region.resources || []).slice(0, 25).forEach((r, ri) => {
    const rId = `rres-${ri}`;
    nodes.push({ id: rId, type: "resourceNode", width: 175, height: 65, data: { ...r }, position: { x: 0, y: 0 } });
    edges_.push(edge(`e-rr-${ri}`, regId, rId, "#1e293b"));
  });

  return { nodes: layout(nodes, edges_, "TB"), edges: edges_ };
}

function buildGlobalGraph(globalResources) {
  const nodes = [], edges_ = [];
  nodes.push({
    id: "g-root", type: "groupNode", width: 185, height: 65,
    data: {
      label: "Global Resources", nodeType: "global_group", active: true,
      count: globalResources.length,
      violations: globalResources.filter(r => r.compliance?.status === "fail").length,
    },
    position: { x: 0, y: 0 },
  });

  const byType = {};
  globalResources.forEach(r => { (byType[r.type] = byType[r.type] || []).push(r); });

  Object.entries(byType).forEach(([type, list], ti) => {
    const meta = tm(type);
    const typeId = `gt-${ti}`;
    nodes.push({
      id: typeId, type: "groupNode", width: 165, height: 55,
      data: { label: meta.label, nodeType: type, count: list.length, violations: list.filter(r => r.compliance?.status === "fail").length, active: true },
      position: { x: 0, y: 0 },
    });
    edges_.push(edge(`e-ggt-${ti}`, "g-root", typeId, `${meta.color}50`));

    list.slice(0, 12).forEach((r, ri) => {
      const rId = `gr-${ti}-${ri}`;
      nodes.push({ id: rId, type: "resourceNode", width: 175, height: 65, data: { ...r }, position: { x: 0, y: 0 } });
      edges_.push(edge(`e-gtr-${rId}`, typeId, rId, "#1e293b"));
    });
  });

  return { nodes: layout(nodes, edges_, "TB"), edges: edges_ };
}

// ─── Inspector Panel ─────────────────────────────────────────────────────────
function InspectorPanel({ node, attribution, onClose }) {
  const [openSec, setOpenSec] = useState({ findings: true, trail: true, config: false, meta: true });
  const toggle = (k) => setOpenSec(s => ({ ...s, [k]: !s[k] }));
  if (!node) return null;

  const style = cs(node.data?.compliance);
  const meta  = tm(node.data?.type || node.type || "default");

  const relatedEvents = (attribution || []).filter(ev => {
    const label = (node.data?.label || "").toLowerCase();
    const type  = (node.data?.type  || "").replace("aws_", "").split("_")[0];
    return (
      (ev.username || "").toLowerCase().includes(label) ||
      label.includes((ev.username || "").toLowerCase()) ||
      (ev.event_name || "").toLowerCase().includes(type)
    );
  }).slice(0, 12);

  const Sec = ({ k, title, children }) => (
    <div style={{ marginBottom: 14 }}>
      <button onClick={() => toggle(k)} style={{ background: "none", border: "none", cursor: "pointer", color: "#64748b", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", padding: "0 0 6px 0", display: "flex", gap: 5, alignItems: "center" }}>
        <span>{openSec[k] ? "▾" : "▸"}</span>{title}
      </button>
      {openSec[k] && children}
    </div>
  );

  return (
    <motion.div
      initial={{ x: 390, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: 390, opacity: 0 }}
      transition={{ type: "spring", damping: 28, stiffness: 220 }}
      style={{
        position: "absolute", right: 0, top: 0, bottom: 0, width: 365,
        background: "#07101f", borderLeft: "1px solid #1a2a4a", zIndex: 80,
        boxShadow: "-24px 0 60px rgba(0,0,0,0.9)", display: "flex", flexDirection: "column",
      }}
    >
      {/* Header */}
      <div style={{ padding: "14px 16px", borderBottom: "1px solid #1a2a4a", background: "#050d1a", flexShrink: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div style={{ display: "flex", gap: 10, alignItems: "center", maxWidth: 300 }}>
            <span style={{ fontSize: 22 }}>{meta.icon}</span>
            <div style={{ overflow: "hidden" }}>
              <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {node.data?.label || node.id}
              </div>
              <div style={{ color: "#475569", fontSize: 10 }}>{meta.label}</div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "#475569", fontSize: 20, lineHeight: 1, paddingTop: 2 }}>✕</button>
        </div>
        <div style={{ marginTop: 10, padding: "8px 10px", background: style.bg, border: `1px solid ${style.border}`, borderRadius: 8, display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ background: style.badge, color: "#000", borderRadius: 4, padding: "2px 8px", fontSize: 10, fontWeight: 700 }}>{style.text}</span>
          {(node.data?.compliance?.failed || 0) > 0
            ? <span style={{ color: "#f87171", fontSize: 11 }}>{node.data.compliance.failed} failing check{node.data.compliance.failed > 1 ? "s" : ""}</span>
            : node.data?.compliance?.status === "pass"
              ? <span style={{ color: "#22c55e", fontSize: 11 }}>All checks passed ✓</span>
              : <span style={{ color: "#94a3b8", fontSize: 11 }}>No compliance data</span>
          }
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: "auto", padding: "14px 16px" }}>

        {/* Compliance findings */}
        <Sec k="findings" title={`Compliance Findings (${node.data?.compliance?.findings?.length || 0})`}>
          {(node.data?.compliance?.findings || []).length === 0
            ? <div style={{ color: "#475569", fontSize: 11, padding: "4px 0 8px" }}>No findings</div>
            : (node.data.compliance.findings).map((f, i) => (
              <div key={i} style={{ background: "#0c1828", borderRadius: 7, padding: 8, marginBottom: 6, borderLeft: `3px solid ${f.status === "FAIL" ? "#ef4444" : "#f59e0b"}` }}>
                <div style={{ color: "#f1f5f9", fontSize: 11, fontWeight: 600 }}>{f.title}</div>
                <div style={{ display: "flex", gap: 6, marginTop: 3 }}>
                  <span style={{ color: "#475569", fontSize: 9 }}>{f.rule_id}</span>
                  <span style={{ color: f.severity === "CRITICAL" || f.severity === "HIGH" ? "#ef4444" : "#f59e0b", fontSize: 9, fontWeight: 700 }}>{f.severity}</span>
                </div>
              </div>
            ))
          }
        </Sec>

        {/* CloudTrail */}
        <Sec k="trail" title={`CloudTrail Activity (${relatedEvents.length})`}>
          {relatedEvents.length === 0
            ? <div style={{ color: "#475569", fontSize: 11, padding: "4px 0 8px" }}>No related events</div>
            : relatedEvents.map((ev, i) => (
              <div key={i} style={{ background: ev.is_suspicious ? "#2d0a0a" : "#0c1828", borderRadius: 7, padding: "7px 8px", marginBottom: 5, borderLeft: `3px solid ${ev.is_suspicious ? "#ef4444" : "#1e293b"}` }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: ev.is_suspicious ? "#ef4444" : "#f1f5f9", fontSize: 11, fontWeight: 600 }}>{ev.event_name}</span>
                  {ev.is_suspicious && <span style={{ color: "#ef4444", fontSize: 9, fontWeight: 700 }}>⚠ SUSPICIOUS</span>}
                </div>
                <div style={{ color: "#94a3b8", fontSize: 9, marginTop: 3 }}>
                  👤 {ev.username || "Unknown"} · 📍 {ev.region || "—"}
                </div>
                {ev.event_time && (
                  <div style={{ color: "#475569", fontSize: 8, marginTop: 2 }}>
                    {new Date(ev.event_time).toLocaleString()}
                    {ev.source_ip && ` · ${ev.source_ip}`}
                  </div>
                )}
              </div>
            ))
          }
        </Sec>

        {/* Config */}
        {node.data?.config && Object.keys(node.data.config).length > 0 && (
          <Sec k="config" title="Configuration">
            <pre style={{ background: "#0c1828", padding: 8, borderRadius: 7, fontSize: 9, overflow: "auto", maxHeight: 200, color: "#7dd3fc", margin: 0, lineHeight: 1.5 }}>
              {JSON.stringify(node.data.config, null, 2)}
            </pre>
          </Sec>
        )}

        {/* Metadata */}
        <Sec k="meta" title="Metadata">
          {[
            { k: "Node ID", v: node.id },
            { k: "Type",    v: node.data?.type },
            { k: "Region",  v: node.data?.region },
          ].filter(x => x.v).map(({ k, v }) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "5px 0", borderBottom: "1px solid #0f172a" }}>
              <span style={{ color: "#475569", fontSize: 10 }}>{k}</span>
              <span style={{ color: "#cbd5e1", fontSize: 10, fontFamily: "monospace", maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" }}>{v}</span>
            </div>
          ))}
        </Sec>
      </div>
    </motion.div>
  );
}

// ─── Left Tree Explorer ──────────────────────────────────────────────────────
function TreeExplorer({ data, currentView, onNavigate }) {
  const [open, setOpen] = useState(new Set(["regions"]));
  const tog = (k) => setOpen(p => { const s = new Set(p); s.has(k) ? s.delete(k) : s.add(k); return s; });
  const ol = data?.org_layer || {};

  const Item = ({ icon, label, count, violations, onClick, active, indent = 0 }) => (
    <div
      onClick={onClick}
      style={{
        display: "flex", alignItems: "center", gap: 7,
        padding: `5px ${10 + indent * 14}px`,
        cursor: "pointer", borderRadius: 5, margin: "1px 5px",
        background: active ? "#0f1f3a" : "transparent",
        color: active ? "#60a5fa" : "#94a3b8", fontSize: 12,
      }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = "#0a1525"; }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = "transparent"; }}
    >
      <span style={{ fontSize: 13 }}>{icon}</span>
      <span style={{ flex: 1 }}>{label}</span>
      {(violations || 0) > 0 && <span style={{ color: "#ef4444", fontSize: 9 }}>⚠{violations}</span>}
      {count != null && <span style={{ color: "#334155", fontSize: 9, background: "#0c1828", borderRadius: 3, padding: "1px 5px" }}>{count}</span>}
    </div>
  );

  const scoreColor = ol.score >= 80 ? "#22c55e" : ol.score >= 60 ? "#f59e0b" : "#ef4444";

  return (
    <div style={{ width: 215, background: "#050d1a", borderRight: "1px solid #131f33", display: "flex", flexDirection: "column", flexShrink: 0 }}>
      {/* Account summary */}
      <div style={{ padding: "12px", borderBottom: "1px solid #131f33", flexShrink: 0 }}>
        <div style={{ color: "#475569", fontSize: 9, textTransform: "uppercase", fontWeight: 700, marginBottom: 4 }}>Explorer</div>
        <div style={{ color: "#f1f5f9", fontSize: 12, fontWeight: 700, fontFamily: "monospace" }}>{ol.account_id || "No Scan Data"}</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 5, marginTop: 8 }}>
          {[
            { v: `${ol.score || 0}%`, c: scoreColor, l: "Score" },
            { v: ol.violations || 0, c: (ol.violations || 0) > 0 ? "#ef4444" : "#22c55e", l: "Fails" },
            { v: ol.total_resources || 0, c: "#60a5fa", l: "Total" },
          ].map(({ v, c, l }) => (
            <div key={l} style={{ background: "#0c1828", borderRadius: 6, padding: "4px 5px", textAlign: "center" }}>
              <div style={{ color: c, fontSize: 11, fontWeight: 700 }}>{v}</div>
              <div style={{ color: "#334155", fontSize: 8 }}>{l}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", paddingTop: 4 }}>
        <Item icon="🔑" label="Account Overview" onClick={() => onNavigate("overview")} active={currentView === "overview"} />

        <Item
          icon="👥" label="Identity & Access"
          count={data?.evidence?.["Identity & Access"]?.count}
          violations={data?.evidence?.["Identity & Access"]?.violations}
          onClick={() => onNavigate("iam")}
          active={currentView === "iam"}
        />

        <div style={{ padding: "8px 10px 3px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={{ color: "#334155", fontSize: 9, textTransform: "uppercase", fontWeight: 700 }}>Regions</span>
          <button onClick={() => tog("regions")} style={{ background: "none", border: "none", cursor: "pointer", color: "#334155", fontSize: 10 }}>
            {open.has("regions") ? "▾" : "▸"}
          </button>
        </div>
        {open.has("regions") && (data?.regions || []).map((r) => (
          <div key={r.name}>
            <Item
              icon={r.cloudtrail ? "🌍" : "🌐"} label={r.name}
              count={r.total} violations={r.violations}
              onClick={() => onNavigate(`region:${r.name}`)}
              active={currentView === `region:${r.name}`}
            />
            {currentView === `region:${r.name}` && (r.vpcs || []).map((vpc, vi) => (
              <Item key={vi} icon="🔷" label={vpc.label || vpc.id} count={(vpc.subnets || []).length} violations={vpc.internet_exposed ? 1 : 0} onClick={() => onNavigate(`region:${r.name}`)} indent={1} active={false} />
            ))}
          </div>
        ))}

        {(data?.global_resources?.length || 0) > 0 && (
          <>
            <div style={{ padding: "8px 10px 3px" }}>
              <span style={{ color: "#334155", fontSize: 9, textTransform: "uppercase", fontWeight: 700 }}>Global</span>
            </div>
            <Item
              icon="🌐" label="Global Resources"
              count={data.global_resources?.length}
              violations={data.global_resources?.filter(r => r.compliance?.status === "fail").length}
              onClick={() => onNavigate("global")}
              active={currentView === "global"}
            />
          </>
        )}
      </div>
    </div>
  );
}

// ─── CloudTrail Timeline (bottom strip) ─────────────────────────────────────
function CloudTrailTimeline({ events }) {
  if (!events?.length) return null;
  const suspicious = events.filter(e => e.is_suspicious).length;
  return (
    <div style={{ height: 155, background: "#050d1a", borderTop: "1px solid #131f33", flexShrink: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "6px 12px", borderBottom: "1px solid #131f33", display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
        <span style={{ fontSize: 13 }}>📝</span>
        <span style={{ color: "#94a3b8", fontSize: 10, fontWeight: 700, textTransform: "uppercase" }}>CloudTrail Activity</span>
        <span style={{ background: "#131f33", color: "#94a3b8", borderRadius: 4, padding: "1px 7px", fontSize: 9 }}>{events.length} events</span>
        {suspicious > 0 && (
          <span style={{ background: "#ef444420", color: "#ef4444", borderRadius: 4, padding: "1px 7px", fontSize: 9, fontWeight: 700 }}>
            ⚠ {suspicious} suspicious
          </span>
        )}
      </div>
      <div style={{ flex: 1, display: "flex", gap: 8, padding: "8px 12px", overflowX: "auto", alignItems: "flex-start" }}>
        {events.map((ev, i) => (
          <div key={i} style={{
            flexShrink: 0, width: 190,
            background: ev.is_suspicious ? "#2d0a0a" : "#0c1828",
            border: `1px solid ${ev.is_suspicious ? "#ef4444" : "#1e293b"}`,
            borderRadius: 7, padding: "7px 9px",
          }}>
            <div style={{ color: ev.is_suspicious ? "#ef4444" : "#f1f5f9", fontSize: 10, fontWeight: 600, marginBottom: 3, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
              {ev.is_suspicious ? "⚠ " : ""}{ev.event_name}
            </div>
            <div style={{ color: "#94a3b8", fontSize: 9 }}>👤 {ev.username || "Unknown"}</div>
            <div style={{ color: "#475569", fontSize: 8, marginTop: 2 }}>
              📍 {ev.region || "—"} {ev.source_ip ? `· ${ev.source_ip}` : ""}
            </div>
            {ev.event_time && (
              <div style={{ color: "#334155", fontSize: 8, marginTop: 1 }}>
                {new Date(ev.event_time).toLocaleString()}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Compliance bar (top right summary) ─────────────────────────────────────
function ComplianceBar({ meta, ol }) {
  if (!meta?.total && !ol?.total_resources) return null;
  const score = meta?.score ?? ol?.score ?? 0;
  const scoreColor = score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : "#ef4444";
  const pills = [
    { label: "Score",   val: `${score}%`,                 color: scoreColor },
    { label: "PASS",    val: meta?.compliant ?? 0,         color: "#22c55e" },
    { label: "FAIL",    val: meta?.violations ?? 0,        color: "#ef4444" },
    { label: "Regions", val: ol?.regions_active ?? 0,      color: "#34d399" },
    { label: "Trail",   val: ol?.cloudtrail_enabled ? "ON" : "OFF", color: ol?.cloudtrail_enabled ? "#22c55e" : "#ef4444" },
  ];
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
      {pills.map(({ label, val, color }) => (
        <div key={label} style={{ background: "#090f1e", borderRadius: 5, padding: "3px 8px", display: "flex", alignItems: "center", gap: 4 }}>
          <span style={{ color, fontSize: 11, fontWeight: 700 }}>{val}</span>
          <span style={{ color: "#334155", fontSize: 9 }}>{label}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────
export default function TopologyView() {
  const [topoData,        setTopoData]        = useState(null);
  const [loading,         setLoading]         = useState(true);
  const [error,           setError]           = useState(null);
  const [currentView,     setCurrentView]     = useState("overview");
  const [selectedNode,    setSelectedNode]    = useState(null);
  const [showTrail,       setShowTrail]       = useState(true);
  const [showExplorer,    setShowExplorer]    = useState(true);
  const [filterCompliance,setFilterCompliance]= useState("all");
  const [nodes, setNodes, onNodesChange]      = useNodesState([]);
  const [edges, setEdges, onEdgesChange]      = useEdgesState([]);

  // ── Fetch ──
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res  = await fetch(`${API}/api/topology`);
      const data = await res.json();
      if (data.error && !data.org_layer?.account_id) {
        setError(data.error);
      } else {
        setTopoData(data);
      }
    } catch (e) {
      setError(e.message || "Network error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ── Rebuild graph when view / filter changes ──
  useEffect(() => {
    if (!topoData) return;

    let result;
    if      (currentView === "overview")          result = buildOverviewGraph(topoData, currentView);
    else if (currentView === "iam")               result = buildIAMGraph(topoData.evidence);
    else if (currentView === "global")            result = buildGlobalGraph(topoData.global_resources || []);
    else if (currentView.startsWith("region:")) {
      const name = currentView.slice(7);
      result = buildRegionGraph((topoData.regions || []).find(r => r.name === name));
    }
    if (!result) return;

    // Apply compliance filter
    if (filterCompliance !== "all") {
      const keep = new Set(
        result.nodes
          .filter(n => {
            const s = (n.data?.compliance?.status || "").toLowerCase();
            if (filterCompliance === "fail") return s === "fail";
            if (filterCompliance === "pass") return s === "pass";
            if (filterCompliance === "warn") return s === "warn" || s === "unknown";
            return true;
          })
          .map(n => n.id)
      );
      // also keep parents that have at least one matching child
      result.edges.forEach(e => {
        if (keep.has(e.target)) keep.add(e.source);
      });
      result.nodes = result.nodes.filter(n => keep.has(n.id));
      result.edges = result.edges.filter(e => keep.has(e.source) && keep.has(e.target));
    }

    setNodes(result.nodes);
    setEdges(result.edges);
  }, [topoData, currentView, filterCompliance, setNodes, setEdges]);

  // ── Node click: navigate groups, inspect resources ──
  const handleNodeClick = useCallback((_, node) => {
    const id = node.id;
    if (id === "g-iam")    { setCurrentView("iam");    setSelectedNode(null); return; }
    if (id === "g-global") { setCurrentView("global"); setSelectedNode(null); return; }
    if (id.startsWith("g-reg-")) {
      const name = id.replace("g-reg-", "");
      setCurrentView(`region:${name}`);
      setSelectedNode(null);
      return;
    }
    setSelectedNode(node);
  }, []);

  const navigate = useCallback((view) => {
    setCurrentView(view);
    setSelectedNode(null);
  }, []);

  // ── Nav pills ──
  const navPills = useMemo(() => {
    const pills = [{ id: "overview", icon: "🔑", label: "Overview" }];
    if (topoData?.evidence?.["Identity & Access"]?.count) pills.push({ id: "iam", icon: "👥", label: "IAM" });
    (topoData?.regions || []).forEach(r => pills.push({ id: `region:${r.name}`, icon: r.cloudtrail ? "🌍" : "🌐", label: r.name }));
    if (topoData?.global_resources?.length) pills.push({ id: "global", icon: "🌐", label: "Global" });
    return pills;
  }, [topoData]);

  return (
    <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", background: "#030a14", overflow: "hidden" }}>

      {/* ── Header ── */}
      <div style={{ padding: "9px 14px", background: "#050d1a", borderBottom: "1px solid #131f33", display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
        <div>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14 }}>AWS Infrastructure Topology</div>
          <div style={{ color: "#334155", fontSize: 10, marginTop: 1 }}>Security · Compliance · Audit Graph</div>
        </div>
        <div style={{ flex: 1 }} />
        {topoData && <ComplianceBar meta={topoData.meta} ol={topoData.org_layer} />}
        <div style={{ display: "flex", gap: 6 }}>
          <select
            value={filterCompliance}
            onChange={e => setFilterCompliance(e.target.value)}
            style={{ background: "#090f1e", border: "1px solid #1e293b", color: "#94a3b8", borderRadius: 5, padding: "4px 8px", fontSize: 11, cursor: "pointer" }}
          >
            <option value="all">All Resources</option>
            <option value="fail">Failures Only</option>
            <option value="pass">Passing Only</option>
            <option value="warn">Warnings</option>
          </select>
          <button onClick={() => setShowTrail(v => !v)}    style={{ padding: "4px 10px", borderRadius: 5, border: "1px solid #131f33", background: showTrail    ? "#0f1f3a" : "#090f1e", color: "#94a3b8", cursor: "pointer", fontSize: 11 }}>📝 Trail</button>
          <button onClick={() => setShowExplorer(v => !v)} style={{ padding: "4px 10px", borderRadius: 5, border: "1px solid #131f33", background: showExplorer ? "#0f1f3a" : "#090f1e", color: "#94a3b8", cursor: "pointer", fontSize: 11 }}>📂 Explorer</button>
          <button onClick={fetchData} disabled={loading}   style={{ padding: "4px 12px", borderRadius: 5, border: "1px solid #131f33", background: "#090f1e", color: "#cbd5e1", cursor: loading ? "not-allowed" : "pointer", fontSize: 11, opacity: loading ? 0.5 : 1 }}>
            {loading ? "Loading…" : "↻ Refresh"}
          </button>
        </div>
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div style={{ padding: "9px 14px", background: "#2d0a0a", color: "#f87171", borderBottom: "1px solid #ef444430", fontSize: 12, flexShrink: 0 }}>
          ❌ {error}
        </div>
      )}

      {/* ── Body ── */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", position: "relative" }}>

        {/* Left Explorer */}
        {showExplorer && topoData && (
          <TreeExplorer data={topoData} currentView={currentView} onNavigate={navigate} />
        )}

        {/* Canvas */}
        <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>

          {/* Loading spinner */}
          {loading && !topoData && (
            <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 14, zIndex: 10 }}>
              <div style={{ width: 44, height: 44, border: "3px solid #131f33", borderTopColor: "#3b82f6", borderRadius: "50%", animation: "spin 1s linear infinite" }} />
              <div style={{ color: "#475569", fontSize: 12 }}>Building topology graph…</div>
            </div>
          )}

          {/* Empty state */}
          {!loading && !topoData && !error && (
            <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 12 }}>
              <div style={{ fontSize: 52 }}>🗺️</div>
              <div style={{ color: "#f1f5f9", fontSize: 15, fontWeight: 700 }}>No topology data</div>
              <div style={{ color: "#475569", fontSize: 12 }}>Run a scan from the Monitoring tab first</div>
            </div>
          )}

          {/* ReactFlow canvas */}
          {topoData && (
            <ReactFlow
              nodes={nodes} edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={handleNodeClick}
              nodeTypes={nodeTypes}
              fitView fitViewOptions={{ padding: 0.15 }}
              minZoom={0.08} maxZoom={2.5}
              style={{ background: "#030a14" }}
            >
              <Background color="#0c1220" gap={22} variant="dots" />
              <Controls style={{ background: "#07101f", border: "1px solid #1e293b", borderRadius: 8 }} />
              <MiniMap
                style={{ background: "#07101f", border: "1px solid #1e293b" }}
                nodeColor={n => cs(n.data?.compliance).border}
                maskColor="rgba(3,10,20,0.85)"
                pannable zoomable
              />

              {/* Nav pills overlay */}
              <div style={{ position: "absolute", top: 12, left: 12, zIndex: 10, display: "flex", gap: 5, flexWrap: "wrap", maxWidth: "60%" }}>
                {navPills.map(({ id, icon, label }) => (
                  <button
                    key={id}
                    onClick={() => navigate(id)}
                    style={{
                      padding: "4px 11px", borderRadius: 20,
                      border: `1px solid ${id === currentView ? "#3b82f6" : "#1e293b"}`,
                      background: id === currentView ? "#1e3a5f" : "#07101f",
                      color: id === currentView ? "#60a5fa" : "#475569",
                      fontSize: 11, cursor: "pointer", fontWeight: id === currentView ? 700 : 400,
                      transition: "all 0.15s",
                    }}
                  >
                    {icon} {label}
                  </button>
                ))}
              </div>

              {/* Legend */}
              <div style={{ position: "absolute", bottom: 12, left: 12, zIndex: 10, display: "flex", gap: 8, background: "#07101f", border: "1px solid #1e293b", borderRadius: 7, padding: "6px 10px" }}>
                {[["#22c55e","PASS"],["#f59e0b","WARN"],["#ef4444","FAIL"],["#334155","N/A"]].map(([c, l]) => (
                  <div key={l} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: c }} />
                    <span style={{ color: "#475569", fontSize: 9 }}>{l}</span>
                  </div>
                ))}
              </div>
            </ReactFlow>
          )}
        </div>

        {/* Right Inspector */}
        <AnimatePresence>
          {selectedNode && (
            <InspectorPanel
              node={selectedNode}
              attribution={topoData?.attribution}
              onClose={() => setSelectedNode(null)}
            />
          )}
        </AnimatePresence>
      </div>

      {/* CloudTrail Timeline */}
      {topoData && showTrail && (
        <CloudTrailTimeline events={topoData.attribution || []} />
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
