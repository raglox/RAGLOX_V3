// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Dashboard Page
// Main dashboard view with stats, network graph, and activity feed
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { StatsGrid } from '@/components/dashboard/StatsGrid'
import { NetworkGraph } from '@/components/dashboard/NetworkGraph'
import { ActivityFeed } from '@/components/dashboard/ActivityFeed'
import { TargetDetailsDrawer } from '@/components/dashboard/TargetDetailsDrawer'
import { HITLApprovalModal } from '@/components/dashboard/HITLApprovalModal'
import { useEventStore } from '@/stores/eventStore'

export function Dashboard() {
  const { pendingApprovals } = useEventStore()
  const [selectedApproval, setSelectedApproval] = React.useState<string | null>(null)
  
  // Show approval modal when new approval comes in
  React.useEffect(() => {
    if (pendingApprovals.length > 0 && !selectedApproval) {
      // Auto-open modal for first pending approval
      // setSelectedApproval(pendingApprovals[0].action_id)
    }
  }, [pendingApprovals, selectedApproval])
  
  const currentApproval = pendingApprovals.find(
    (a) => a.action_id === selectedApproval
  )
  
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary-dark">Dashboard</h1>
          <p className="text-text-secondary-dark">
            Real-time security operations overview
          </p>
        </div>
      </div>
      
      {/* Stats Grid */}
      <StatsGrid />
      
      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Graph - Takes 2 columns */}
        <div className="lg:col-span-2">
          <NetworkGraph />
        </div>
        
        {/* Activity Feed - Takes 1 column */}
        <div className="lg:col-span-1">
          <ActivityFeed />
        </div>
      </div>
      
      {/* Target Details Drawer */}
      <TargetDetailsDrawer />
      
      {/* HITL Approval Modal */}
      <HITLApprovalModal
        approval={currentApproval ?? null}
        onClose={() => setSelectedApproval(null)}
      />
    </div>
  )
}
