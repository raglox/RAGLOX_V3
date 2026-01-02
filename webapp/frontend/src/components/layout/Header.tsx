// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Header Component
// Professional header with clear borders and Emergency Stop button
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  OctagonX,
  Bot,
  Bell,
  Wifi,
  WifiOff,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { useEventStore, selectConnectionStatus } from '@/stores/eventStore'

export function Header() {
  const connectionStatus = useEventStore(selectConnectionStatus)
  const pendingApprovals = useEventStore((state) => state.pendingApprovals)
  const toggleAIPanel = useEventStore((state) => state.toggleAIPanel)
  const isAIPanelOpen = useEventStore((state) => state.isAIPanelOpen)
  const isSidebarCollapsed = useEventStore((state) => state.isSidebarCollapsed)
  const [isStopModalOpen, setIsStopModalOpen] = React.useState(false)
  
  const handleEmergencyStop = async () => {
    // In production, this would call the API to stop all missions
    console.log('Emergency stop triggered')
    setIsStopModalOpen(false)
    
    // Call API to stop mission
    try {
      const response = await fetch('/api/missions/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      if (!response.ok) {
        console.error('Failed to stop mission')
      }
    } catch (error) {
      console.error('Emergency stop failed:', error)
    }
  }
  
  return (
    <header className="fixed top-0 right-0 left-0 z-30 h-16 border-b-2 border-border-dark bg-bg-card-dark/95 backdrop-blur-md shadow-lg">
      <div className={cn(
        "flex h-full items-center justify-between px-6 transition-all duration-300",
        isSidebarCollapsed ? "ml-16" : "ml-64"
      )}>
        {/* Left Section - Breadcrumb / Title */}
        <div className="flex items-center gap-4">
          <div className="flex flex-col">
            <h1 className="text-lg font-semibold text-text-primary-dark tracking-tight">
              Security Operations
            </h1>
            <span className="text-xs text-text-muted-dark font-mono">RAGLOX Control Center</span>
          </div>
          <div className="h-8 w-px bg-border-dark/50 mx-2" />
          <ConnectionIndicator status={connectionStatus} />
        </div>
        
        {/* Right Section - Actions */}
        <div className="flex items-center gap-4">
          {/* Notifications */}
          <Button
            variant="ghost"
            size="icon"
            className="relative rounded-xl border-2 border-transparent hover:border-border-dark/50"
            onClick={() => {}}
          >
            <Bell className="h-5 w-5 text-text-secondary-dark" />
            {pendingApprovals.length > 0 && (
              <span className="absolute -top-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full bg-critical text-xs font-bold text-white shadow-lg">
                {pendingApprovals.length}
              </span>
            )}
          </Button>
          
          {/* AI Assistant Toggle */}
          <Button
            variant={isAIPanelOpen ? 'secondary' : 'ghost'}
            size="icon"
            onClick={toggleAIPanel}
            title="AI Assistant"
            className="rounded-xl border-2 border-transparent hover:border-border-dark/50"
          >
            <Bot className="h-5 w-5 text-text-secondary-dark" />
          </Button>
          
          {/* Divider */}
          <div className="h-8 w-px bg-border-dark/50" />
          
          {/* Emergency Stop Button */}
          <Button
            variant="outline"
            className="border-2 border-critical text-critical hover:bg-critical hover:text-white transition-all duration-200 gap-2 px-4 rounded-xl font-bold shadow-lg shadow-critical/10"
            onClick={() => setIsStopModalOpen(true)}
          >
            <OctagonX className="h-4 w-4" />
            <span>EMERGENCY STOP</span>
          </Button>
        </div>
      </div>
      
      {/* Emergency Stop Confirmation Modal */}
      {isStopModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl border-2 border-critical/30 bg-bg-card-dark p-6 shadow-2xl">
            <div className="flex items-center gap-4 text-critical mb-6">
              <div className="p-3 rounded-xl bg-critical/10 border-2 border-critical/30">
                <OctagonX className="h-8 w-8" />
              </div>
              <div>
                <h2 className="text-xl font-bold">Emergency Stop</h2>
                <p className="text-sm text-text-muted-dark">This action cannot be undone</p>
              </div>
            </div>
            <p className="text-text-secondary-dark mb-6 leading-relaxed">
              This will immediately halt all running missions and active operations.
              Are you sure you want to proceed?
            </p>
            <div className="flex justify-end gap-3">
              <Button 
                variant="ghost" 
                onClick={() => setIsStopModalOpen(false)}
                className="rounded-xl"
              >
                Cancel
              </Button>
              <Button 
                variant="destructive" 
                onClick={handleEmergencyStop}
                className="rounded-xl font-bold"
              >
                Confirm Stop
              </Button>
            </div>
          </div>
        </div>
      )}
    </header>
  )
}

// Connection Status Indicator
interface ConnectionIndicatorProps {
  status: 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
}

function ConnectionIndicator({ status }: ConnectionIndicatorProps) {
  const statusConfig = {
    connected: {
      icon: Wifi,
      color: 'text-success',
      bgColor: 'bg-success/10 border-success/30',
      dotColor: 'bg-success',
      label: 'Connected',
    },
    connecting: {
      icon: Wifi,
      color: 'text-warning',
      bgColor: 'bg-warning/10 border-warning/30',
      dotColor: 'bg-warning animate-pulse',
      label: 'Connecting...',
    },
    reconnecting: {
      icon: Wifi,
      color: 'text-warning',
      bgColor: 'bg-warning/10 border-warning/30',
      dotColor: 'bg-warning animate-pulse',
      label: 'Reconnecting...',
    },
    disconnected: {
      icon: WifiOff,
      color: 'text-critical',
      bgColor: 'bg-critical/10 border-critical/30',
      dotColor: 'bg-critical',
      label: 'Disconnected',
    },
  }
  
  const config = statusConfig[status]
  const Icon = config.icon
  
  return (
    <div
      className={cn(
        'inline-flex items-center gap-2 px-3 py-1.5 rounded-xl border-2',
        config.bgColor
      )}
    >
      <span className={cn('w-2 h-2 rounded-full', config.dotColor)} />
      <Icon className={cn('h-4 w-4', config.color)} />
      <span className={cn('text-xs font-medium', config.color)}>{config.label}</span>
    </div>
  )
}
