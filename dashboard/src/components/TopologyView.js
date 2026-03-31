import React, { useState, useEffect, useCallback, useMemo } from 'react';
import ReactFlow, { 
  addEdge, 
  Background, 
  Controls, 
  MiniMap,
  useNodesState,
  useEdgesState,
  Panel,
  MarkerType
} from 'reactflow';
import 'reactflow/dist/style.css';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ExternalLink, 
  Info, 
  AlertTriangle, 
  CheckCircle, 
  Shield, 
  Database, 
  Server, 
  Cloud,
  Layers,
  Settings,
  X
} from 'lucide-react';

// --- Custom Node Components ---

const ServiceNode = ({ data }) => {
  const isFailed = data.status === 'fail';
  const Icon = data.type?.includes('db') || data.type?.includes('rds') ? Database :
               data.type?.includes('ec2') || data.type?.includes('vm') || data.type?.includes('instance') ? Server :
               data.type?.includes('s3') || data.type?.includes('storage') ? Layers :
               data.type?.includes('iam') || data.type?.includes('security') ? Shield : Cloud;

  return (
    <div className={`service-node ${isFailed ? 'failed' : 'passed'}`} style={{
      padding: '10px',
      borderRadius: '8px',
      background: 'rgba(30, 41, 59, 0.9)',
      border: `1px solid ${isFailed ? '#ef4444' : '#10b981'}`,
      color: '#fff',
      display: 'flex',
      alignItems: 'center',
      gap: '10px',
      minWidth: '180px',
      boxShadow: isFailed ? '0 0 15px rgba(239, 68, 68, 0.4)' : '0 0 10px rgba(16, 185, 129, 0.2)',
      backdropFilter: 'blur(4px)',
      position: 'relative'
    }}>
      <div style={{ 
        background: isFailed ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
        padding: '6px',
        borderRadius: '6px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center'
      }}>
        <Icon size={18} color={isFailed ? '#ef4444' : '#10b981'} />
      </div>
      <div style={{ flex: 1, overflow: 'hidden' }}>
        <div style={{ fontSize: '11px', opacity: 0.6, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
          {data.type?.split('_').pop() || 'Resource'}
        </div>
        <div style={{ fontSize: '13px', fontWeight: '500', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {data.label}
        </div>
      </div>
      {isFailed && (
        <motion.div 
          animate={{ scale: [1, 1.2, 1] }} 
          transition={{ repeat: Infinity, duration: 2 }}
          style={{ position: 'absolute', top: -5, right: -5 }}
        >
          <AlertTriangle size={14} color="#ef4444" fill="#ef444433" />
        </motion.div>
      )}
    </div>
  );
};

const GroupNode = ({ data }) => {
  return (
    <div className="group-node" style={{
      width: '100%',
      height: '100%',
      borderRadius: '12px',
      border: '1px solid rgba(255, 255, 255, 0.1)',
      background: 'rgba(15, 23, 42, 0.3)',
      backdropFilter: 'blur(8px)',
      padding: '10px',
      pointerEvents: 'none' // Allow interaction with children
    }}>
      <div style={{ 
        position: 'absolute', 
        top: -25, 
        left: 0, 
        color: 'rgba(255,255,255,0.7)', 
        fontSize: '11px', 
        fontWeight: '600',
        textTransform: 'uppercase',
        letterSpacing: '1px',
        display: 'flex',
        alignItems: 'center',
        gap: '5px'
      }}>
        <Settings size={12} /> {data.label}
      </div>
    </div>
  );
};

const nodeTypes = {
  service: ServiceNode,
  resource: ServiceNode, // Alias
  group: GroupNode
};

// --- Dagre Layout Helper ---
import dagre from 'dagre';

const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

const getLayoutedElements = (nodes, edges, direction = 'TB') => {
  dagreGraph.setGraph({ rankdir: direction, nodesep: 100, ranksep: 200 });

  nodes.forEach((node) => {
    // For groups, we use larger dimensions
    const isGroup = node.type === 'group';
    dagreGraph.setNode(node.id, { 
      width: isGroup ? 800 : 180, 
      height: isGroup ? 600 : 80 
    });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  return nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    const parent = node.parentNode ? nodes.find(n => n.id === node.parentNode) : null;
    const parentPos = parent ? dagreGraph.node(parent.id) : { x: 0, y: 0 };

    // If it has a parent, position is relative to parent's top-left
    // Dagre returns center coordinates, so we subtract half-width/height
    const x = nodeWithPosition.x - (node.style?.width || (node.type === 'group' ? 800 : 180)) / 2;
    const y = nodeWithPosition.y - (node.style?.height || (node.type === 'group' ? 600 : 80)) / 2;

    if (parent) {
      const parentX = parentPos.x - (parent.style?.width || 800) / 2;
      const parentY = parentPos.y - (parent.style?.height || 600) / 2;
      node.position = {
        x: x - parentX,
        y: y - parentY,
      };
    } else {
      node.position = { x, y };
    }
    
    return node;
  });
};

// --- Main Component ---

const TopologyView = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [selectedResource, setSelectedResource] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(new Date());

  const fetchTopology = useCallback(async () => {
    try {
      const response = await fetch('http://localhost:8000/api/topology');
      const data = await response.json();
      
      const layouted = getLayoutedElements(data.nodes || [], data.edges || []);
      
      setNodes(layouted);
      setEdges((data.edges || []).map(edge => ({
        ...edge,
        markerEnd: { type: MarkerType.ArrowClosed, color: 'rgba(255,255,255,0.2)' }
      })));
      setLoading(false);
      setLastUpdate(new Date());
    } catch (error) {
      console.error('Error fetching topology:', error);
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    fetchTopology();
    
    const ws = new WebSocket('ws://localhost:8000/api/ws/topology');
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'INITIAL_STATE' || message.type === 'RESOURCE_UPDATED') {
         fetchTopology();
      }
    };
    return () => ws.close();
  }, [fetchTopology]);

  const onNodeClick = (evt, node) => {
    if (node.type === 'resource' || node.type === 'service' || node.data?.config) {
      setSelectedResource(node);
    }
  };

  return (
    <div style={{ width: '100%', height: 'calc(100vh - 100px)', background: '#020617', borderRadius: '16px', border: '1px solid #1e293b', overflow: 'hidden', position: 'relative' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={nodeTypes}
        fitView
        snapToGrid
        snapGrid={[20, 20]}
        style={{ background: '#020617' }}
      >
        <Background color="#1e293b" gap={20} size={1} />
        <Controls showInteractive={false} style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
        <MiniMap 
          nodeColor={(n) => {
            if (n.type === 'group') return '#1e293b';
            return n.data?.status === 'fail' ? '#ef4444' : '#10b981';
          }}
          maskColor="rgba(2, 6, 23, 0.7)"
          style={{ background: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b' }}
        />
        
        <Panel position="top-right" style={{ background: 'rgba(15, 23, 42, 0.8)', backdropFilter: 'blur(12px)', padding: '16px', borderRadius: '12px', border: '1px solid #1e293b', color: '#fff', minWidth: '220px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Cloud size={18} color="#3b82f6" />
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: '600' }}>Global Satellite View</h3>
          </div>
          <div style={{ fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ opacity: 0.6 }}>Synchronized with Organzation API</div>
            <div style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '5px' }}>
               <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} />
               Real-time Active
            </div>
            <div style={{ marginTop: '8px', opacity: 0.4, fontSize: '10px' }}>LAST SYNC: {lastUpdate.toLocaleTimeString()}</div>
          </div>
          <button 
            onClick={fetchTopology}
            className="refresh-btn"
            style={{ 
              marginTop: '16px', 
              width: '100%', 
              background: '#3b82f6', 
              border: 'none', 
              padding: '8px', 
              borderRadius: '8px', 
              color: '#fff', 
              fontWeight: '500', 
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px'
            }}
          >
            <Layers size={14} /> Re-scan Organization
          </button>
        </Panel>

        <Panel position="bottom-center" style={{ background: 'rgba(15, 23, 42, 0.8)', backdropFilter: 'blur(12px)', padding: '10px 20px', borderRadius: '20px', border: '1px solid #1e293b', color: '#aaa', fontSize: '12px', marginBottom: '20px' }}>
            <div style={{ display: 'flex', gap: '20px' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }} /> Compliant</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }} /> Violation</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><div style={{ width: 8, height: 8, borderRadius: '2px', background: 'rgba(255,255,255,0.1)', border: '1px solid #3b82f6' }} /> Container</span>
            </div>
        </Panel>
      </ReactFlow>

      {/* Resource Inspector Side Drawer */}
      <AnimatePresence>
        {selectedResource && (
          <motion.div 
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            style={{ 
              position: 'absolute', 
              top: 0, 
              right: 0, 
              width: '400px', 
              height: '100%', 
              background: '#0f172a', 
              borderLeft: '1px solid #1e293b', 
              zIndex: 1001, 
              boxShadow: '-10px 0 30px rgba(0,0,0,0.5)',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            <div style={{ padding: '24px', borderBottom: '1px solid #1e293b', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ padding: '8px', background: 'rgba(59, 130, 246, 0.1)', borderRadius: '10px' }}>
                   <Info size={20} color="#3b82f6" />
                </div>
                <h2 style={{ margin: 0, fontSize: '18px', color: '#fff' }}>Resource Inspector</h2>
              </div>
              <button onClick={() => setSelectedResource(null)} style={{ background: 'none', border: 'none', color: '#aaa', cursor: 'pointer' }}><X size={20} /></button>
            </div>
            
            <div style={{ flex: 1, overflowY: 'auto', padding: '24px' }}>
                <div style={{ marginBottom: '24px' }}>
                    <div style={{ fontSize: '12px', color: '#64748b', textTransform: 'uppercase', marginBottom: '8px' }}>Asset Identifier</div>
                    <div style={{ background: '#020617', padding: '12px', borderRadius: '8px', border: '1px solid #1e293b', color: '#3b82f6', fontFamily: 'monospace', fontSize: '13px' }}>
                        {selectedResource.id}
                    </div>
                </div>

                <div style={{ marginBottom: '24px' }}>
                    <div style={{ fontSize: '12px', color: '#64748b', textTransform: 'uppercase', marginBottom: '8px' }}>Security Status</div>
                    {selectedResource.data?.status === 'fail' ? (
                        <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', padding: '16px', borderRadius: '12px', display: 'flex', gap: '12px' }}>
                            <AlertTriangle color="#ef4444" size={24} />
                            <div>
                                <div style={{ color: '#ef4444', fontWeight: '600', fontSize: '14px' }}>Critical Configuration Drift</div>
                                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px' }}>CIS AWS Benchmark 1.2: Ensure MFA is enabled for all IAM users.</div>
                            </div>
                        </div>
                    ) : (
                        <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.2)', padding: '16px', borderRadius: '12px', display: 'flex', gap: '12px' }}>
                            <CheckCircle color="#10b981" size={24} />
                            <div>
                                <div style={{ color: '#10b981', fontWeight: '600', fontSize: '14px' }}>Compliant with Policy</div>
                                <div style={{ color: '#94a3b8', fontSize: '12px', marginTop: '4px' }}>Resource adheres to the current security baseline.</div>
                            </div>
                        </div>
                    )}
                </div>

                <div style={{ marginBottom: '24px' }}>
                    <div style={{ fontSize: '12px', color: '#64748b', textTransform: 'uppercase', marginBottom: '8px' }}>Live Configuration Data</div>
                    <pre style={{ background: '#020617', padding: '16px', borderRadius: '12px', border: '1px solid #1e293b', color: '#94a3b8', fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(selectedResource.data?.config || { message: "No extended telemetry available" }, null, 2)}
                    </pre>
                </div>
            </div>

            <div style={{ padding: '24px', background: '#020617', borderTop: '1px solid #1e293b' }}>
                <button style={{ width: '100%', background: 'rgba(59, 130, 246, 0.1)', color: '#3b82f6', border: '1px solid rgba(59, 130, 246, 0.2)', padding: '12px', borderRadius: '10px', fontSize: '14px', fontWeight: '600', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                    <ExternalLink size={16} /> Open in Cloud Console
                </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {loading && (
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#020617', zIndex: 1000, color: '#fff' }}>
          <motion.div 
            animate={{ rotate: 360 }} 
            transition={{ repeat: Infinity, duration: 1.5, ease: 'linear' }}
            style={{ width: 40, height: 40, border: '3px solid rgba(59, 130, 246, 0.1)', borderTopColor: '#3b82f6', borderRadius: '50%' }} 
          />
          <div style={{ marginLeft: '15px', fontSize: '16px', fontWeight: '500', color: '#64748b' }}>Analyzing Infrastructure Hierarchy...</div>
        </div>
      )}
      
      {/* Styles for nodes (since vanilla CSS is preferred but inline is harder for complex hover) */}
      <style>{`
        .failed {
          animation: redGlow 2s infinite alternate;
        }
        @keyframes redGlow {
          from { box-shadow: 0 0 10px rgba(239, 68, 68, 0.2); }
          to { box-shadow: 0 0 25px rgba(239, 68, 68, 0.5); }
        }
        .service-node:hover {
          background: rgba(30, 41, 59, 1) !important;
          transform: translateY(-2px);
          transition: all 0.2s ease;
        }
        .refresh-btn:hover {
          background: #2563eb !important;
          transform: scale(1.02);
        }
      `}</style>
    </div>
  );
};

export default TopologyView;
