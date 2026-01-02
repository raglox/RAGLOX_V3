// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Frontend Types
// Type definitions matching backend models
// ═══════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════

export type MissionStatus =
  | 'created'
  | 'starting'
  | 'running'
  | 'paused'
  | 'waiting_for_approval'
  | 'completing'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'archived'

export type TargetStatus =
  | 'discovered'
  | 'scanning'
  | 'scanned'
  | 'exploiting'
  | 'exploited'
  | 'owned'
  | 'failed'

export type Priority = 'critical' | 'high' | 'medium' | 'low'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type SessionType = 'shell' | 'meterpreter' | 'ssh' | 'rdp' | 'wmi' | 'winrm' | 'smb'

export type SessionStatus = 'active' | 'idle' | 'dead'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired'

export type ActionType =
  | 'exploit'
  | 'write'
  | 'lateral'
  | 'privesc'
  | 'exfil'
  | 'persistence'
  | 'destructive'

// ═══════════════════════════════════════════════════════════════
// WebSocket Event Types
// ═══════════════════════════════════════════════════════════════

export type WebSocketEventType =
  | 'connected'
  | 'pong'
  | 'error'
  | 'new_target'
  | 'new_vuln'
  | 'new_cred'
  | 'new_session'
  | 'goal_achieved'
  | 'status_change'
  | 'statistics'
  | 'approval_request'
  | 'approval_response'
  | 'chat_message'
  | 'task_execution_log'

export interface WebSocketMessage {
  type: WebSocketEventType
  mission_id?: string
  message?: string
  timestamp: string
  data?: Record<string, unknown>
}

// ═══════════════════════════════════════════════════════════════
// Entity Types
// ═══════════════════════════════════════════════════════════════

export interface Target {
  target_id: string
  ip: string
  hostname?: string
  os?: string
  status: TargetStatus
  priority: Priority
  risk_score?: number
  ports: Record<string, string>
  subnet?: string
}

export interface Vulnerability {
  vuln_id: string
  target_id: string
  type: string
  name?: string
  severity: Severity
  cvss?: number
  status: string
  exploit_available: boolean
}

export interface Credential {
  cred_id: string
  target_id: string
  type: string
  username?: string
  domain?: string
  privilege_level: string
  verified: boolean
  source?: string
}

export interface Session {
  session_id: string
  target_id: string
  type: SessionType
  user?: string
  privilege: string
  status: SessionStatus
  established_at: string
  last_activity: string
}

export interface Mission {
  mission_id: string
  name: string
  status: MissionStatus
  scope: string[]
  goals: Record<string, string>
  statistics: MissionStats
  target_count: number
  vuln_count: number
  created_at?: string
  started_at?: string
  completed_at?: string
}

export interface MissionStats {
  targets_discovered: number
  vulns_found: number
  creds_harvested: number
  sessions_established: number
  goals_achieved: number
  goals_total: number
  completion_percentage: number
  critical_vulns?: number
  high_vulns?: number
  active_sessions?: number
}

// ═══════════════════════════════════════════════════════════════
// Event Types
// ═══════════════════════════════════════════════════════════════

export interface TaskExecutionLog {
  id: string
  timestamp: string
  level: 'debug' | 'info' | 'warning' | 'error'
  message: string
  task_id?: string
  task_type?: string
  specialist?: string
  target_id?: string
}

export interface NewTargetEvent {
  target_id: string
  ip: string
  hostname?: string
  priority?: Priority
}

export interface VulnerabilityFoundEvent {
  vuln_id: string
  target_id: string
  severity: Severity
  type: string
}

export interface ApprovalRequest {
  action_id: string
  action_type: ActionType
  action_description: string
  target_ip?: string
  target_hostname?: string
  risk_level: RiskLevel
  risk_reasons: string[]
  potential_impact?: string
  command_preview?: string
  requested_at: string
  expires_at?: string
}

export interface ChatMessage {
  id: string
  role: 'user' | 'system' | 'assistant'
  content: string
  timestamp: string
  related_task_id?: string
  related_action_id?: string
}

// ═══════════════════════════════════════════════════════════════
// Activity Feed Types
// ═══════════════════════════════════════════════════════════════

export type ActivityType =
  | 'target_discovered'
  | 'vuln_found'
  | 'session_established'
  | 'goal_achieved'
  | 'task_started'
  | 'task_completed'
  | 'task_failed'
  | 'approval_required'
  | 'status_change'
  | 'log'

export interface ActivityItem {
  id: string
  type: ActivityType
  title: string
  description?: string
  timestamp: string
  severity?: Severity
  metadata?: Record<string, unknown>
}

// ═══════════════════════════════════════════════════════════════
// Network Graph Types
// ═══════════════════════════════════════════════════════════════

export interface GraphNode {
  id: string
  name: string
  type: 'target' | 'subnet' | 'group'
  ip?: string
  os?: string
  status: TargetStatus | 'cluster'
  priority?: Priority
  childCount?: number
  children?: string[]
  x?: number
  y?: number
  fx?: number
  fy?: number
}

export interface GraphLink {
  source: string
  target: string
  type: 'lateral' | 'discovery' | 'attack_path'
}

export interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

// ═══════════════════════════════════════════════════════════════
// UI State Types
// ═══════════════════════════════════════════════════════════════

export interface Toast {
  id: string
  type: 'success' | 'warning' | 'error' | 'info'
  title: string
  description?: string
  action?: {
    label: string
    onClick: () => void
  }
  duration?: number
}

export interface DrawerState {
  isOpen: boolean
  type?: 'target' | 'approval' | 'ai'
  data?: Target | ApprovalRequest | null
}
