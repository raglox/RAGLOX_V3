// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - NetworkGraph Component
// Interactive network visualization with semantic clustering
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Network } from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { useEventStore } from '@/stores/eventStore'
import type { GraphNode, GraphLink } from '@/types'

// Node colors based on status
const statusColors: Record<string, string> = {
  discovered: '#3B82F6',  // Blue
  scanning: '#F59E0B',    // Yellow
  scanned: '#10B981',     // Green
  exploiting: '#F59E0B',  // Yellow
  exploited: '#EF4444',   // Red
  owned: '#DC2626',       // Dark Red
  failed: '#6B7280',      // Gray
  cluster: '#8B5CF6',     // Purple for clusters
}

// Priority colors
const priorityColors: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#3B82F6',
  low: '#10B981',
}

export function NetworkGraph() {
  const containerRef = React.useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = React.useState({ width: 600, height: 400 })
  
  // Get state with stable selectors - use shallow comparison for objects
  const graphData = useEventStore((state) => state.graphData)
  const targetCount = useEventStore((state) => state.targets.size)
  const updateGraphData = useEventStore((state) => state.updateGraphData)
  const setSelectedTarget = useEventStore((state) => state.setSelectedTarget)
  
  // Local copy of graph data to avoid issues with react-force-graph
  const [localGraphData, setLocalGraphData] = React.useState<{ nodes: GraphNode[], links: GraphLink[] }>({ nodes: [], links: [] })
  
  // Update local graph data when store changes
  React.useEffect(() => {
    setLocalGraphData({
      nodes: [...graphData.nodes],
      links: [...graphData.links],
    })
  }, [graphData.nodes, graphData.links])
  
  // Update graph data when targets change
  React.useEffect(() => {
    updateGraphData()
  }, [targetCount, updateGraphData])
  
  // Handle container resize
  React.useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { width, height } = containerRef.current.getBoundingClientRect()
        setDimensions({ width, height: Math.max(height, 300) })
      }
    }
    
    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [])
  
  // Node click handler
  const handleNodeClick = React.useCallback(
    (node: { id?: string | number; type?: string }) => {
      if (node.type === 'target' && node.id) {
        setSelectedTarget(String(node.id))
      }
    },
    [setSelectedTarget]
  )
  
  // Custom node rendering
  const nodeCanvasObject = React.useCallback(
    (
      node: { x?: number; y?: number; name?: string; type?: string; status?: string; priority?: string; childCount?: number },
      ctx: CanvasRenderingContext2D,
      globalScale: number
    ) => {
      const label = node.name || ''
      const fontSize = 10 / globalScale
      const nodeSize = node.type === 'subnet' ? 16 : 12
      
      // Draw node circle
      ctx.beginPath()
      ctx.arc(node.x || 0, node.y || 0, nodeSize, 0, 2 * Math.PI)
      ctx.fillStyle = node.type === 'subnet'
        ? statusColors.cluster
        : statusColors[node.status as string] || statusColors.discovered
      ctx.fill()
      
      // Draw border for priority
      if (node.priority) {
        ctx.strokeStyle = priorityColors[node.priority] || '#3B82F6'
        ctx.lineWidth = 2 / globalScale
        ctx.stroke()
      }
      
      // Draw child count for clusters
      if (node.type === 'subnet' && node.childCount) {
        ctx.font = `bold ${fontSize * 1.2}px Inter`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillStyle = '#FFFFFF'
        ctx.fillText(String(node.childCount), node.x || 0, node.y || 0)
      }
      
      // Draw label
      ctx.font = `${fontSize}px Inter`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = '#94A3B8'
      ctx.fillText(label, node.x || 0, (node.y || 0) + nodeSize + 2)
    },
    []
  )
  
  // Link rendering
  const linkColor = React.useCallback((link: { type?: string }) => {
    switch (link.type) {
      case 'attack_path':
        return '#EF4444'
      case 'lateral':
        return '#F59E0B'
      default:
        return '#334155'
    }
  }, [])
  
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Network Map</CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs">
              {localGraphData.nodes.length} nodes
            </Badge>
            <Badge variant="outline" className="text-xs">
              {targetCount} targets
            </Badge>
          </div>
        </div>
        
        {/* Legend */}
        <div className="flex flex-wrap gap-3 mt-2">
          <LegendItem color={statusColors.discovered} label="Discovered" />
          <LegendItem color={statusColors.scanning} label="Scanning" />
          <LegendItem color={statusColors.scanned} label="Scanned" />
          <LegendItem color={statusColors.exploited} label="Exploited" />
          <LegendItem color={statusColors.cluster} label="Subnet" />
        </div>
      </CardHeader>
      
      <CardContent className="p-0 h-[400px]" ref={containerRef}>
        {localGraphData.nodes.length > 0 ? (
          <ForceGraph2D
            graphData={localGraphData}
            width={dimensions.width}
            height={dimensions.height}
            backgroundColor="#0F172A"
            nodeCanvasObject={nodeCanvasObject}
            nodeCanvasObjectMode={() => 'replace'}
            linkColor={linkColor}
            linkWidth={1.5}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            onNodeClick={handleNodeClick}
            cooldownTime={2000}
            d3AlphaDecay={0.02}
            d3VelocityDecay={0.3}
          />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-text-muted-dark">
            <Network className="h-12 w-12 mb-3 opacity-50" />
            <p className="text-sm">No targets discovered yet</p>
            <p className="text-xs mt-1">Start a mission to see the network map</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// Legend Item Component
function LegendItem({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <div
        className="h-2.5 w-2.5 rounded-full"
        style={{ backgroundColor: color }}
      />
      <span className="text-xs text-text-muted-dark">{label}</span>
    </div>
  )
}
