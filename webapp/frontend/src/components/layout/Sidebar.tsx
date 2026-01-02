// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Sidebar Component
// Clean, collapsible enterprise sidebar with improved borders
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  LayoutDashboard,
  Target,
  Brain,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'

interface NavItem {
  icon: React.ElementType
  label: string
  href: string
  badge?: number
}

const navItems: NavItem[] = [
  { icon: LayoutDashboard, label: 'Dashboard', href: '/' },
  { icon: Target, label: 'Targets', href: '/targets' },
  { icon: Brain, label: 'Intelligence', href: '/intelligence' },
  { icon: Settings, label: 'Settings', href: '/settings' },
]

export function Sidebar() {
  const { isSidebarCollapsed, toggleSidebar, missionStats } = useEventStore()
  
  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 h-screen bg-bg-card-dark border-r-2 border-border-dark',
        'flex flex-col transition-all duration-300 ease-in-out shadow-xl',
        isSidebarCollapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo Section */}
      <div className="flex h-16 items-center border-b-2 border-border-dark px-4 bg-bg-elevated-dark/30">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-royal-blue to-royal-blue-dark shadow-lg shadow-royal-blue/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          {!isSidebarCollapsed && (
            <div className="flex flex-col">
              <span className="text-lg font-bold text-text-primary-dark tracking-tight">RAGLOX</span>
              <span className="text-xs text-text-muted-dark font-mono">v3.0</span>
            </div>
          )}
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-3">
        <div className="mb-3 px-3">
          {!isSidebarCollapsed && (
            <span className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider">
              Navigation
            </span>
          )}
        </div>
        {navItems.map((item) => (
          <NavLink
            key={item.href}
            item={item}
            isCollapsed={isSidebarCollapsed}
            badge={item.label === 'Targets' ? missionStats.targets_discovered : undefined}
          />
        ))}
      </nav>
      
      {/* Stats Summary (when expanded) */}
      {!isSidebarCollapsed && (
        <div className="border-t-2 border-border-dark p-4 bg-bg-elevated-dark/20">
          <div className="mb-3">
            <span className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider">
              Quick Stats
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <StatBox label="Targets" value={missionStats.targets_discovered} variant="default" />
            <StatBox label="Vulns" value={missionStats.vulns_found} variant="warning" />
            <StatBox label="Sessions" value={missionStats.sessions_established} variant="success" />
            <StatBox label="Critical" value={missionStats.critical_vulns ?? 0} variant="critical" />
          </div>
        </div>
      )}
      
      {/* Collapse Toggle */}
      <button
        onClick={toggleSidebar}
        className={cn(
          'flex h-14 items-center justify-center border-t-2 border-border-dark',
          'text-text-muted-dark hover:text-text-primary-dark hover:bg-bg-elevated-dark',
          'transition-all duration-200'
        )}
      >
        {isSidebarCollapsed ? (
          <ChevronRight className="h-5 w-5" />
        ) : (
          <div className="flex items-center gap-2 text-xs font-medium">
            <ChevronLeft className="h-4 w-4" />
            Collapse
          </div>
        )}
      </button>
    </aside>
  )
}

// Navigation Link Component
interface NavLinkProps {
  item: NavItem
  isCollapsed: boolean
  badge?: number
}

function NavLink({ item, isCollapsed, badge }: NavLinkProps) {
  const Icon = item.icon
  const isActive = window.location.pathname === item.href
  
  return (
    <a
      href={item.href}
      className={cn(
        'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium',
        'transition-all duration-200 border-2',
        isActive
          ? 'bg-royal-blue/10 text-royal-blue border-royal-blue/30 shadow-sm'
          : 'text-text-secondary-dark hover:text-text-primary-dark hover:bg-bg-elevated-dark border-transparent hover:border-border-dark/50',
        isCollapsed && 'justify-center px-0'
      )}
      title={isCollapsed ? item.label : undefined}
    >
      <Icon className="h-5 w-5 flex-shrink-0" />
      {!isCollapsed && (
        <>
          <span className="flex-1">{item.label}</span>
          {badge !== undefined && badge > 0 && (
            <span className="rounded-full bg-royal-blue px-2.5 py-1 text-xs font-semibold text-white shadow-sm">
              {badge}
            </span>
          )}
        </>
      )}
    </a>
  )
}

// Stats Box Component
interface StatBoxProps {
  label: string
  value: number
  variant?: 'default' | 'critical' | 'warning' | 'success'
}

const statBoxStyles = {
  default: {
    value: 'text-royal-blue',
    bg: 'bg-royal-blue/5 border-royal-blue/20',
  },
  critical: {
    value: 'text-critical',
    bg: 'bg-critical/5 border-critical/20',
  },
  warning: {
    value: 'text-warning',
    bg: 'bg-warning/5 border-warning/20',
  },
  success: {
    value: 'text-success',
    bg: 'bg-success/5 border-success/20',
  },
}

function StatBox({ label, value, variant = 'default' }: StatBoxProps) {
  const styles = statBoxStyles[variant]
  
  return (
    <div className={cn('rounded-xl p-3 border-2', styles.bg)}>
      <div className={cn('text-xl font-bold', styles.value)}>
        {value}
      </div>
      <div className="text-xs text-text-muted-dark font-medium">{label}</div>
    </div>
  )
}
