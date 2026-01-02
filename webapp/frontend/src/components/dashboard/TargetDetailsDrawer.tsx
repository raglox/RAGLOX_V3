// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Target Details Drawer
// Slide-over panel showing detailed target information
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Server,
  Monitor,
  Globe,
  Shield,
  Bug,
  Terminal,
  RefreshCw,
  Crosshair,
} from 'lucide-react'
import { Drawer } from '@/components/ui/Drawer'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { useEventStore, selectSelectedTarget, selectVulnerabilities, selectSessions } from '@/stores/eventStore'
import type { Vulnerability, Session } from '@/types'

export function TargetDetailsDrawer() {
  const { selectedTargetId, setSelectedTarget, addToast } = useEventStore()
  const selectedTarget = useEventStore(selectSelectedTarget)
  const allVulnerabilities = useEventStore(selectVulnerabilities)
  const allSessions = useEventStore(selectSessions)
  
  // Filter vulnerabilities and sessions for this target
  const targetVulns = allVulnerabilities.filter(
    (v) => v.target_id === selectedTargetId
  )
  const targetSessions = allSessions.filter(
    (s) => s.target_id === selectedTargetId
  )
  
  const handleClose = () => setSelectedTarget(null)
  
  const handleScanAgain = async () => {
    addToast({
      type: 'info',
      title: 'Scan Initiated',
      description: `Starting scan for ${selectedTarget?.ip}`,
    })
    // In production, this would call the API
  }
  
  const handleExploit = async () => {
    if (targetVulns.length === 0) {
      addToast({
        type: 'warning',
        title: 'No Vulnerabilities',
        description: 'No exploitable vulnerabilities found on this target.',
      })
      return
    }
    
    addToast({
      type: 'info',
      title: 'Exploit Queued',
      description: 'Exploitation attempt has been queued.',
    })
    // In production, this would call the API
  }
  
  if (!selectedTarget) return null
  
  const statusColors: Record<string, 'success' | 'warning' | 'critical' | 'secondary'> = {
    discovered: 'secondary',
    scanning: 'warning',
    scanned: 'success',
    exploiting: 'warning',
    exploited: 'critical',
    owned: 'critical',
    failed: 'secondary',
  }
  
  const priorityColors: Record<string, 'critical' | 'warning' | 'success' | 'secondary'> = {
    critical: 'critical',
    high: 'warning',
    medium: 'secondary',
    low: 'success',
  }
  
  return (
    <Drawer
      isOpen={!!selectedTargetId}
      onClose={handleClose}
      title={selectedTarget.hostname || selectedTarget.ip}
      description="Target Details"
      width="lg"
    >
      {/* Status and Priority */}
      <div className="flex items-center gap-2 mb-6">
        <Badge variant={statusColors[selectedTarget.status]}>
          {selectedTarget.status}
        </Badge>
        <Badge variant={priorityColors[selectedTarget.priority ?? 'medium']}>
          {selectedTarget.priority ?? 'medium'} priority
        </Badge>
        {selectedTarget.risk_score && (
          <Badge variant="outline">
            Risk: {selectedTarget.risk_score.toFixed(1)}
          </Badge>
        )}
      </div>
      
      {/* Basic Info */}
      <Card className="p-4 mb-4">
        <h4 className="text-sm font-medium text-text-secondary-dark mb-3">
          System Information
        </h4>
        <div className="grid grid-cols-2 gap-4">
          <InfoRow icon={Globe} label="IP Address" value={selectedTarget.ip} />
          <InfoRow
            icon={Monitor}
            label="Hostname"
            value={selectedTarget.hostname || 'Unknown'}
          />
          <InfoRow
            icon={Server}
            label="Operating System"
            value={selectedTarget.os || 'Unknown'}
          />
          <InfoRow
            icon={Shield}
            label="Status"
            value={selectedTarget.status}
          />
        </div>
      </Card>
      
      {/* Open Ports */}
      <Card className="p-4 mb-4">
        <h4 className="text-sm font-medium text-text-secondary-dark mb-3">
          Open Ports ({Object.keys(selectedTarget.ports).length})
        </h4>
        {Object.keys(selectedTarget.ports).length > 0 ? (
          <div className="space-y-2">
            {Object.entries(selectedTarget.ports).map(([port, service]) => (
              <div
                key={port}
                className="flex items-center justify-between py-2 px-3 rounded bg-bg-elevated-dark"
              >
                <span className="font-mono text-sm text-royal-blue">{port}</span>
                <span className="text-sm text-text-secondary-dark">{service}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-text-muted-dark">No ports discovered yet</p>
        )}
      </Card>
      
      {/* Vulnerabilities */}
      <Card className="p-4 mb-4">
        <h4 className="text-sm font-medium text-text-secondary-dark mb-3">
          <Bug className="h-4 w-4 inline mr-1" />
          Vulnerabilities ({targetVulns.length})
        </h4>
        {targetVulns.length > 0 ? (
          <div className="space-y-2">
            {targetVulns.map((vuln) => (
              <VulnRow key={vuln.vuln_id} vuln={vuln} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-text-muted-dark">No vulnerabilities found</p>
        )}
      </Card>
      
      {/* Active Sessions */}
      <Card className="p-4 mb-6">
        <h4 className="text-sm font-medium text-text-secondary-dark mb-3">
          <Terminal className="h-4 w-4 inline mr-1" />
          Active Sessions ({targetSessions.length})
        </h4>
        {targetSessions.length > 0 ? (
          <div className="space-y-2">
            {targetSessions.map((session) => (
              <SessionRow key={session.session_id} session={session} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-text-muted-dark">No active sessions</p>
        )}
      </Card>
      
      {/* Action Buttons */}
      <div className="flex gap-2">
        <Button variant="outline" className="flex-1 gap-2" onClick={handleScanAgain}>
          <RefreshCw className="h-4 w-4" />
          Scan Again
        </Button>
        <Button
          className="flex-1 gap-2"
          onClick={handleExploit}
          disabled={targetVulns.length === 0}
        >
          <Crosshair className="h-4 w-4" />
          Exploit
        </Button>
      </div>
    </Drawer>
  )
}

// Info Row Component
function InfoRow({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType
  label: string
  value: string
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="h-4 w-4 text-text-muted-dark" />
      <div>
        <p className="text-xs text-text-muted-dark">{label}</p>
        <p className="text-sm text-text-primary-dark">{value}</p>
      </div>
    </div>
  )
}

// Vulnerability Row Component
function VulnRow({ vuln }: { vuln: Vulnerability }) {
  const severityColors: Record<string, 'critical' | 'warning' | 'success' | 'secondary'> = {
    critical: 'critical',
    high: 'warning',
    medium: 'secondary',
    low: 'success',
    info: 'secondary',
  }
  
  return (
    <div className="flex items-center justify-between py-2 px-3 rounded bg-bg-elevated-dark">
      <div className="flex-1">
        <p className="text-sm text-text-primary-dark">{vuln.type}</p>
        {vuln.name && (
          <p className="text-xs text-text-muted-dark">{vuln.name}</p>
        )}
      </div>
      <div className="flex items-center gap-2">
        {vuln.cvss && (
          <span className="text-xs font-mono text-text-muted-dark">
            CVSS: {vuln.cvss.toFixed(1)}
          </span>
        )}
        <Badge variant={severityColors[vuln.severity]} className="text-xs">
          {vuln.severity}
        </Badge>
        {vuln.exploit_available && (
          <Badge variant="critical" className="text-xs">
            Exploit
          </Badge>
        )}
      </div>
    </div>
  )
}

// Session Row Component
function SessionRow({ session }: { session: Session }) {
  const statusColors: Record<string, 'success' | 'warning' | 'secondary'> = {
    active: 'success',
    idle: 'warning',
    dead: 'secondary',
  }
  
  return (
    <div className="flex items-center justify-between py-2 px-3 rounded bg-bg-elevated-dark">
      <div className="flex items-center gap-2">
        <Terminal className="h-4 w-4 text-text-muted-dark" />
        <div>
          <p className="text-sm text-text-primary-dark">{session.type}</p>
          {session.user && (
            <p className="text-xs text-text-muted-dark">User: {session.user}</p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Badge variant={statusColors[session.status]} className="text-xs">
          {session.status}
        </Badge>
        <Badge variant="outline" className="text-xs">
          {session.privilege}
        </Badge>
      </div>
    </div>
  )
}
