// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - StatsGrid Component
// 4 simple cards showing key metrics
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Target,
  Bug,
  AlertTriangle,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Card, CardContent } from '@/components/ui/Card'
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
  default: 'text-text-primary-dark',
  critical: 'text-critical',
  warning: 'text-warning',
  success: 'text-success',
}

const iconBgStyles = {
  default: 'bg-royal-blue/10 text-royal-blue',
  critical: 'bg-critical/10 text-critical',
  warning: 'bg-warning/10 text-warning',
  success: 'bg-success/10 text-success',
}

function StatCard({ title, value, icon: Icon, trend, variant = 'default' }: StatCardProps) {
  return (
    <Card className="hover:border-border-dark/80 transition-colors">
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-text-secondary-dark">{title}</p>
            <p className={cn('text-3xl font-bold mt-1', variantStyles[variant])}>
              {value.toLocaleString()}
            </p>
            {trend && (
              <p
                className={cn(
                  'text-xs mt-1',
                  trend.isPositive ? 'text-success' : 'text-critical'
                )}
              >
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}% from last hour
              </p>
            )}
          </div>
          <div className={cn('p-3 rounded-lg', iconBgStyles[variant])}>
            <Icon className="h-6 w-6" />
          </div>
        </div>
      </CardContent>
    </Card>
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
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="Targets Discovered"
        value={missionStats.targets_discovered}
        icon={Target}
        variant="default"
      />
      <StatCard
        title="Vulnerabilities Found"
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
