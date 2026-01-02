// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - StatsGrid Component
// 4 professional metric cards with clear borders and shadows
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Target,
  Bug,
  AlertTriangle,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'

interface StatCardProps {
  title: string
  value: number
  icon: React.ElementType
  trend?: {
    value: number
    isPositive: boolean
  }
  variant?: 'default' | 'critical' | 'warning' | 'success'
}

const variantStyles = {
  default: {
    value: 'text-royal-blue',
    icon: 'bg-royal-blue/10 text-royal-blue border border-royal-blue/20',
    border: 'border-royal-blue/30 hover:border-royal-blue/50',
  },
  critical: {
    value: 'text-critical',
    icon: 'bg-critical/10 text-critical border border-critical/20',
    border: 'border-critical/30 hover:border-critical/50',
  },
  warning: {
    value: 'text-warning',
    icon: 'bg-warning/10 text-warning border border-warning/20',
    border: 'border-warning/30 hover:border-warning/50',
  },
  success: {
    value: 'text-success',
    icon: 'bg-success/10 text-success border border-success/20',
    border: 'border-success/30 hover:border-success/50',
  },
}

function StatCard({ title, value, icon: Icon, trend, variant = 'default' }: StatCardProps) {
  const styles = variantStyles[variant]
  
  return (
    <div
      className={cn(
        'relative rounded-xl border-2 bg-bg-card-dark p-5 shadow-lg',
        'transition-all duration-200 hover:shadow-xl hover:-translate-y-0.5',
        styles.border
      )}
    >
      {/* Top accent line */}
      <div
        className={cn(
          'absolute top-0 left-4 right-4 h-1 rounded-b-full',
          variant === 'default' && 'bg-royal-blue',
          variant === 'critical' && 'bg-critical',
          variant === 'warning' && 'bg-warning',
          variant === 'success' && 'bg-success'
        )}
      />
      
      <div className="flex items-start justify-between pt-2">
        <div className="space-y-2">
          <p className="text-sm font-medium text-text-secondary-dark uppercase tracking-wide">
            {title}
          </p>
          <p className={cn('text-4xl font-bold tracking-tight', styles.value)}>
            {value.toLocaleString()}
          </p>
          {trend && (
            <p
              className={cn(
                'text-xs font-medium mt-2',
                trend.isPositive ? 'text-success' : 'text-critical'
              )}
            >
              {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}% from last hour
            </p>
          )}
        </div>
        <div className={cn('p-3 rounded-xl', styles.icon)}>
          <Icon className="h-7 w-7" />
        </div>
      </div>
    </div>
  )
}

export function StatsGrid() {
  const missionStats = useEventStore((state) => state.missionStats)
  const sessions = useEventStore((state) => state.sessions)
  
  // Calculate active tasks (sessions in this context) - memoize to avoid recalculation
  const activeSessions = React.useMemo(() => 
    Array.from(sessions.values()).filter((s) => s.status === 'active').length
  , [sessions])
  
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
      <StatCard
        title="Targets Discovered"
        value={missionStats.targets_discovered}
        icon={Target}
        variant="default"
      />
      <StatCard
        title="Vulnerabilities"
        value={missionStats.vulns_found}
        icon={Bug}
        variant="warning"
      />
      <StatCard
        title="Critical Risks"
        value={missionStats.critical_vulns ?? 0}
        icon={AlertTriangle}
        variant="critical"
      />
      <StatCard
        title="Active Sessions"
        value={activeSessions}
        icon={Activity}
        variant="success"
      />
    </div>
  )
}
