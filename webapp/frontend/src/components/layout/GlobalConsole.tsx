// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Global Console Component
// Professional collapsible footer bar (VS Code terminal style)
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  ChevronUp,
  ChevronDown,
  Terminal,
  AlertCircle,
  AlertTriangle,
  Info,
  Bug,
  Trash2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatTimestamp } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { useEventStore, selectLastLog } from '@/stores/eventStore'
import type { TaskExecutionLog } from '@/types'

const logIcons = {
  debug: Bug,
  info: Info,
  warning: AlertTriangle,
  error: AlertCircle,
}

const logColors = {
  debug: 'text-text-muted-dark',
  info: 'text-info',
  warning: 'text-warning',
  error: 'text-critical',
}

const logBgColors = {
  debug: 'bg-text-muted-dark/5',
  info: 'bg-info/5',
  warning: 'bg-warning/5',
  error: 'bg-critical/5',
}

export function GlobalConsole() {
  const isConsoleExpanded = useEventStore((state) => state.isConsoleExpanded)
  const toggleConsole = useEventStore((state) => state.toggleConsole)
  const logs = useEventStore((state) => state.logs)
  const clearLogs = useEventStore((state) => state.clearLogs)
  const isSidebarCollapsed = useEventStore((state) => state.isSidebarCollapsed)
  const lastLog = useEventStore(selectLastLog)
  const consoleRef = React.useRef<HTMLDivElement>(null)
  
  // Auto-scroll to bottom when new logs arrive
  React.useEffect(() => {
    if (isConsoleExpanded && consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [logs.length, isConsoleExpanded])
  
  return (
    <div
      className={cn(
        'fixed bottom-0 right-0 z-30 border-t-2 border-border-dark bg-bg-card-dark shadow-2xl',
        'transition-all duration-300 ease-in-out',
        isSidebarCollapsed ? 'left-16' : 'left-64',
        isConsoleExpanded ? 'h-72' : 'h-12'
      )}
    >
      {/* Header Bar */}
      <div
        className="flex h-12 items-center justify-between px-5 cursor-pointer hover:bg-bg-elevated-dark/30 border-b border-border-dark/50"
        onClick={toggleConsole}
      >
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-royal-blue/10 border border-royal-blue/20">
              <Terminal className="h-4 w-4 text-royal-blue" />
            </div>
            <span className="text-sm font-semibold text-text-primary-dark">Console</span>
          </div>
          
          {/* Log count badge */}
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-bg-elevated-dark border border-border-dark text-xs font-medium text-text-muted-dark">
            {logs.length} logs
          </span>
          
          {/* Last log preview (when collapsed) */}
          {!isConsoleExpanded && lastLog && (
            <>
              <div className="h-5 w-px bg-border-dark/50" />
              <LogPreview log={lastLog} />
            </>
          )}
        </div>
        
        <div className="flex items-center gap-3">
          {isConsoleExpanded && (
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 rounded-lg border border-transparent hover:border-border-dark/50"
              onClick={(e) => {
                e.stopPropagation()
                clearLogs()
              }}
              title="Clear logs"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          )}
          
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 rounded-lg border border-transparent hover:border-border-dark/50"
            onClick={(e) => {
              e.stopPropagation()
              toggleConsole()
            }}
          >
            {isConsoleExpanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronUp className="h-4 w-4" />
            )}
          </Button>
        </div>
      </div>
      
      {/* Expanded Console Content */}
      {isConsoleExpanded && (
        <div
          ref={consoleRef}
          className="h-[calc(100%-3rem)] overflow-y-auto font-mono text-sm p-3 bg-bg-dark/50"
        >
          {logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-text-muted-dark">
              <Terminal className="h-8 w-8 opacity-30 mb-3" />
              <span className="text-sm">No logs yet. Waiting for events...</span>
            </div>
          ) : (
            <div className="space-y-1">
              {logs.map((log) => (
                <LogEntry key={log.id} log={log} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Log Preview (single line for collapsed state)
function LogPreview({ log }: { log: TaskExecutionLog }) {
  const Icon = logIcons[log.level]
  
  return (
    <div className="flex items-center gap-2 text-sm overflow-hidden max-w-md">
      <Icon className={cn('h-3.5 w-3.5 flex-shrink-0', logColors[log.level])} />
      <span className="text-text-muted-dark text-xs font-mono">
        {formatTimestamp(log.timestamp)}
      </span>
      <span className={cn('truncate text-xs', logColors[log.level])}>
        {log.message}
      </span>
    </div>
  )
}

// Full Log Entry (for expanded console)
function LogEntry({ log }: { log: TaskExecutionLog }) {
  const Icon = logIcons[log.level]
  
  return (
    <div className={cn(
      'flex items-start gap-3 py-2 px-3 rounded-lg border border-transparent',
      'hover:border-border-dark/30 transition-colors',
      logBgColors[log.level]
    )}>
      <Icon className={cn('h-4 w-4 flex-shrink-0 mt-0.5', logColors[log.level])} />
      
      <span className="text-text-muted-dark text-xs flex-shrink-0 w-20 font-mono">
        {formatTimestamp(log.timestamp)}
      </span>
      
      {log.specialist && (
        <span className="text-royal-blue text-xs flex-shrink-0 w-28 truncate font-semibold">
          [{log.specialist}]
        </span>
      )}
      
      <span className={cn('flex-1 text-xs', logColors[log.level])}>
        {log.message}
      </span>
      
      {log.target_id && (
        <span className="text-text-muted-dark text-xs font-mono px-2 py-0.5 rounded bg-bg-elevated-dark border border-border-dark/30">
          {log.target_id.slice(0, 8)}
        </span>
      )}
    </div>
  )
}
