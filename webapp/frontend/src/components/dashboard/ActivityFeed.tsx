// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - ActivityFeed Component
// Clean list of recent events with timestamps
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Target,
  Bug,
  Terminal,
  Trophy,
  AlertTriangle,
  RefreshCw,
  Wifi,
  FileText,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatTimestamp } from '@/lib/utils'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { useEventStore } from '@/stores/eventStore'
import type { ActivityItem, ActivityType, Severity } from '@/types'

// Activity icons
const activityIcons: Record<ActivityType, React.ElementType> = {
  target_discovered: Target,
  vuln_found: Bug,
  session_established: Terminal,
  goal_achieved: Trophy,
  task_started: RefreshCw,
  task_completed: RefreshCw,
  task_failed: AlertTriangle,
  approval_required: AlertTriangle,
  status_change: Wifi,
  log: FileText,
}

// Activity colors
const activityColors: Record<ActivityType, string> = {
  target_discovered: 'text-royal-blue',
  vuln_found: 'text-warning',
  session_established: 'text-success',
  goal_achieved: 'text-success',
  task_started: 'text-info',
  task_completed: 'text-success',
  task_failed: 'text-critical',
  approval_required: 'text-warning',
  status_change: 'text-info',
  log: 'text-text-muted-dark',
}

// Severity badges
const severityVariants: Record<Severity, 'critical' | 'warning' | 'success' | 'secondary'> = {
  critical: 'critical',
  high: 'warning',
  medium: 'secondary',
  low: 'success',
  info: 'secondary',
}

export function ActivityFeed() {
  const { activities } = useEventStore()
  
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">Recent Activity</CardTitle>
          <Badge variant="outline" className="text-xs">
            {activities.length} events
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-0">
        <div className="max-h-[400px] overflow-y-auto">
          {activities.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-text-muted-dark">
              <FileText className="h-8 w-8 mb-2 opacity-50" />
              <p className="text-sm">No activity yet</p>
            </div>
          ) : (
            <div className="divide-y divide-border-dark">
              {activities.map((activity) => (
                <ActivityItem key={activity.id} activity={activity} />
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

// Single Activity Item
function ActivityItem({ activity }: { activity: ActivityItem }) {
  const Icon = activityIcons[activity.type] || FileText
  const colorClass = activityColors[activity.type] || 'text-text-muted-dark'
  
  return (
    <div className="flex items-start gap-3 p-4 hover:bg-bg-elevated-dark/30 transition-colors">
      {/* Icon */}
      <div className={cn('flex-shrink-0 mt-0.5', colorClass)}>
        <Icon className="h-4 w-4" />
      </div>
      
      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary-dark">
            {activity.title}
          </span>
          {activity.severity && (
            <Badge variant={severityVariants[activity.severity]} className="text-xs">
              {activity.severity}
            </Badge>
          )}
        </div>
        {activity.description && (
          <p className="text-sm text-text-secondary-dark mt-0.5 truncate">
            {activity.description}
          </p>
        )}
      </div>
      
      {/* Timestamp */}
      <span className="text-xs text-text-muted-dark flex-shrink-0">
        {formatTimestamp(activity.timestamp)}
      </span>
    </div>
  )
}
