// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Header Component
// Minimalist header with Emergency Stop button
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
import { Badge } from '@/components/ui/Badge'
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
    <header className="fixed top-0 right-0 left-0 z-30 h-16 border-b border-border-dark bg-bg-card-dark/95 backdrop-blur-sm">
      <div className={cn(
        "flex h-full items-center justify-between px-4 transition-all duration-300",
        isSidebarCollapsed ? "ml-16" : "ml-64"
      )}>
        {/* Left Section - Breadcrumb / Title */}
        <div className="flex items-center gap-4">
          <h1 className="text-lg font-semibold text-text-primary-dark">
            Security Operations
          </h1>
          <ConnectionIndicator status={connectionStatus} />
        </div>
        
        {/* Right Section - Actions */}
        <div className="flex items-center gap-3">
          {/* Notifications */}
          <Button
            variant="ghost"
            size="icon"
            className="relative"
            onClick={() => {}}
          >
            <Bell className="h-5 w-5 text-text-secondary-dark" />
            {pendingApprovals.length > 0 && (
              <span className="absolute -top-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full bg-critical text-xs text-white">
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
          >
            <Bot className="h-5 w-5 text-text-secondary-dark" />
          </Button>
          
          {/* Emergency Stop Button */}
          <Button
            variant="outline"
            className="border-critical text-critical hover:bg-critical hover:text-white transition-colors gap-2"
            onClick={() => setIsStopModalOpen(true)}
          >
            <OctagonX className="h-4 w-4" />
            <span className="font-semibold">STOP</span>
          </Button>
        </div>
      </div>
      
      {/* Emergency Stop Confirmation Modal */}
      {isStopModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-border-dark bg-bg-card-dark p-6 shadow-xl">
            <div className="flex items-center gap-3 text-critical mb-4">
              <OctagonX className="h-8 w-8" />
              <h2 className="text-xl font-bold">Emergency Stop</h2>
            </div>
            <p className="text-text-secondary-dark mb-6">
              This will immediately halt all running missions and active operations.
              This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <Button variant="ghost" onClick={() => setIsStopModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="destructive" onClick={handleEmergencyStop}>
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
      bgColor: 'bg-success/20',
      label: 'Connected',
    },
    connecting: {
      icon: Wifi,
      color: 'text-warning',
      bgColor: 'bg-warning/20',
      label: 'Connecting...',
    },
    reconnecting: {
      icon: Wifi,
      color: 'text-warning',
      bgColor: 'bg-warning/20',
      label: 'Reconnecting...',
    },
    disconnected: {
      icon: WifiOff,
      color: 'text-critical',
      bgColor: 'bg-critical/20',
      label: 'Disconnected',
    },
  }
  
  const config = statusConfig[status]
  const Icon = config.icon
  
  return (
    <Badge
      variant="outline"
      className={cn(
        'gap-1.5 px-2 py-1',
        config.bgColor,
        config.color,
        'border-current'
      )}
    >
      <Icon className={cn('h-3 w-3', status === 'connected' && 'animate-pulse')} />
      <span className="text-xs">{config.label}</span>
    </Badge>
  )
}
