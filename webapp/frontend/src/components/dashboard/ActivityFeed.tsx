// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - ActivityFeed Component
// Professional activity feed with clear separators
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
  Clock,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatTimestamp } from '@/lib/utils'
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
const activityColors: Record<ActivityType, { bg: string; text: string; border: string }> = {
  target_discovered: { bg: 'bg-royal-blue/10', text: 'text-royal-blue', border: 'border-royal-blue/30' },
  vuln_found: { bg: 'bg-warning/10', text: 'text-warning', border: 'border-warning/30' },
  session_established: { bg: 'bg-success/10', text: 'text-success', border: 'border-success/30' },
  goal_achieved: { bg: 'bg-success/10', text: 'text-success', border: 'border-success/30' },
  task_started: { bg: 'bg-info/10', text: 'text-info', border: 'border-info/30' },
  task_completed: { bg: 'bg-success/10', text: 'text-success', border: 'border-success/30' },
  task_failed: { bg: 'bg-critical/10', text: 'text-critical', border: 'border-critical/30' },
  approval_required: { bg: 'bg-warning/10', text: 'text-warning', border: 'border-warning/30' },
  status_change: { bg: 'bg-info/10', text: 'text-info', border: 'border-info/30' },
  log: { bg: 'bg-text-muted-dark/10', text: 'text-text-muted-dark', border: 'border-text-muted-dark/30' },
}

// Severity badges
const severityStyles: Record<Severity, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-critical/10', text: 'text-critical', border: 'border-critical/30' },
  high: { bg: 'bg-warning/10', text: 'text-warning', border: 'border-warning/30' },
  medium: { bg: 'bg-info/10', text: 'text-info', border: 'border-info/30' },
  low: { bg: 'bg-success/10', text: 'text-success', border: 'border-success/30' },
  info: { bg: 'bg-text-muted-dark/10', text: 'text-text-secondary-dark', border: 'border-text-muted-dark/30' },
}

export function ActivityFeed() {
  const { activities } = useEventStore()
  
  return (
    <div className="rounded-xl border-2 border-border-dark bg-bg-card-dark shadow-lg overflow-hidden h-full">
      {/* Card Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-border-dark bg-bg-elevated-dark/30">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-success/10 border border-success/20">
            <Clock className="h-5 w-5 text-success" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-text-primary-dark">Recent Activity</h3>
            <p className="text-xs text-text-muted-dark">Live event stream</p>
          </div>
        </div>
        
        {/* Events Count */}
        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-bg-elevated-dark border border-border-dark text-xs font-medium text-text-secondary-dark">
          <span className="w-2 h-2 rounded-full bg-success animate-pulse"></span>
          {activities.length} events
        </span>
      </div>
      
      {/* Activity List */}
      <div className="max-h-[440px] overflow-y-auto">
        {activities.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-text-muted-dark bg-bg-dark/30">
            <div className="p-4 rounded-2xl bg-bg-elevated-dark/50 border border-border-dark/50 mb-4">
              <FileText className="h-10 w-10 opacity-40" />
            </div>
            <p className="text-sm font-medium">No activity yet</p>
            <p className="text-xs mt-1 text-text-muted-dark/70">Events will appear here as they occur</p>
          </div>
        ) : (
          <div className="divide-y divide-border-dark/50">
            {activities.map((activity, index) => (
              <ActivityItemComponent key={activity.id} activity={activity} isFirst={index === 0} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Single Activity Item
function ActivityItemComponent({ activity, isFirst }: { activity: ActivityItem; isFirst: boolean }) {
  const Icon = activityIcons[activity.type] || FileText
  const colors = activityColors[activity.type] || activityColors.log
  
  return (
    <div className={cn(
      'flex items-start gap-4 p-4 hover:bg-bg-elevated-dark/30 transition-colors',
      isFirst && 'bg-bg-elevated-dark/20'
    )}>
      {/* Icon with colored background */}
      <div className={cn(
        'flex-shrink-0 p-2 rounded-lg border',
        colors.bg,
        colors.border
      )}>
        <Icon className={cn('h-4 w-4', colors.text)} />
      </div>
      
      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-text-primary-dark">
            {activity.title}
          </span>
          {activity.severity && (
            <span className={cn(
              'inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium border',
              severityStyles[activity.severity].bg,
              severityStyles[activity.severity].text,
              severityStyles[activity.severity].border
            )}>
              {activity.severity.toUpperCase()}
            </span>
          )}
        </div>
        {activity.description && (
          <p className="text-sm text-text-secondary-dark mt-1 line-clamp-2">
            {activity.description}
          </p>
        )}
      </div>
      
      {/* Timestamp */}
      <span className="text-xs text-text-muted-dark flex-shrink-0 font-mono">
        {formatTimestamp(activity.timestamp)}
      </span>
    </div>
  )
}
