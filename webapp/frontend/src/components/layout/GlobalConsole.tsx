// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Global Console Component
// Collapsible footer bar (VS Code terminal style)
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
        'fixed bottom-0 right-0 z-30 border-t border-border-dark bg-bg-card-dark',
        'transition-all duration-300 ease-in-out',
        isSidebarCollapsed ? 'left-16' : 'left-64',
        isConsoleExpanded ? 'h-64' : 'h-10'
      )}
    >
      {/* Header Bar */}
      <div
        className="flex h-10 items-center justify-between px-4 cursor-pointer hover:bg-bg-elevated-dark/50"
        onClick={toggleConsole}
      >
        <div className="flex items-center gap-3">
          <Terminal className="h-4 w-4 text-text-muted-dark" />
          <span className="text-sm font-medium text-text-secondary-dark">Console</span>
          
          {/* Last log preview (when collapsed) */}
          {!isConsoleExpanded && lastLog && (
            <LogPreview log={lastLog} />
          )}
        </div>
        
        <div className="flex items-center gap-2">
          {isConsoleExpanded && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6"
              onClick={(e) => {
                e.stopPropagation()
                clearLogs()
              }}
              title="Clear logs"
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
          
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
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
          className="h-[calc(100%-2.5rem)] overflow-y-auto font-mono text-sm p-2"
        >
          {logs.length === 0 ? (
            <div className="flex items-center justify-center h-full text-text-muted-dark">
              <span>No logs yet. Waiting for events...</span>
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
    <div className="flex items-center gap-2 text-sm overflow-hidden">
      <Icon className={cn('h-3 w-3 flex-shrink-0', logColors[log.level])} />
      <span className="text-text-muted-dark text-xs">
        {formatTimestamp(log.timestamp)}
      </span>
      <span className={cn('truncate', logColors[log.level])}>
        {log.message}
      </span>
    </div>
  )
}

// Full Log Entry (for expanded console)
function LogEntry({ log }: { log: TaskExecutionLog }) {
  const Icon = logIcons[log.level]
  
  return (
    <div className="flex items-start gap-2 py-1 hover:bg-bg-elevated-dark/30 rounded px-2">
      <Icon className={cn('h-4 w-4 flex-shrink-0 mt-0.5', logColors[log.level])} />
      
      <span className="text-text-muted-dark text-xs flex-shrink-0 w-20">
        {formatTimestamp(log.timestamp)}
      </span>
      
      {log.specialist && (
        <span className="text-royal-blue text-xs flex-shrink-0 w-24 truncate">
          [{log.specialist}]
        </span>
      )}
      
      <span className={cn('flex-1', logColors[log.level])}>
        {log.message}
      </span>
      
      {log.target_id && (
        <span className="text-text-muted-dark text-xs">
          target:{log.target_id.slice(0, 8)}
        </span>
      )}
    </div>
  )
}
