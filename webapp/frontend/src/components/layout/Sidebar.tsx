// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Sidebar Component
// Clean, collapsible enterprise sidebar
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
        'fixed left-0 top-0 z-40 h-screen bg-bg-card-dark border-r border-border-dark',
        'flex flex-col transition-all duration-300 ease-in-out',
        isSidebarCollapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo Section */}
      <div className="flex h-16 items-center border-b border-border-dark px-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-royal-blue">
            <Shield className="h-5 w-5 text-white" />
          </div>
          {!isSidebarCollapsed && (
            <div className="flex flex-col">
              <span className="text-lg font-bold text-text-primary-dark">RAGLOX</span>
              <span className="text-xs text-text-muted-dark">v3.0</span>
            </div>
          )}
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 space-y-1 p-2">
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
        <div className="border-t border-border-dark p-4">
          <div className="grid grid-cols-2 gap-2 text-center">
            <StatBox label="Targets" value={missionStats.targets_discovered} />
            <StatBox label="Vulns" value={missionStats.vulns_found} />
            <StatBox label="Sessions" value={missionStats.sessions_established} />
            <StatBox label="Critical" value={missionStats.critical_vulns ?? 0} variant="critical" />
          </div>
        </div>
      )}
      
      {/* Collapse Toggle */}
      <button
        onClick={toggleSidebar}
        className={cn(
          'flex h-12 items-center justify-center border-t border-border-dark',
          'text-text-muted-dark hover:text-text-primary-dark hover:bg-bg-elevated-dark',
          'transition-colors'
        )}
      >
        {isSidebarCollapsed ? (
          <ChevronRight className="h-5 w-5" />
        ) : (
          <ChevronLeft className="h-5 w-5" />
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
        'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium',
        'transition-colors hover:bg-bg-elevated-dark',
        isActive
          ? 'bg-royal-blue/10 text-royal-blue'
          : 'text-text-secondary-dark hover:text-text-primary-dark',
        isCollapsed && 'justify-center px-0'
      )}
      title={isCollapsed ? item.label : undefined}
    >
      <Icon className="h-5 w-5 flex-shrink-0" />
      {!isCollapsed && (
        <>
          <span className="flex-1">{item.label}</span>
          {badge !== undefined && badge > 0 && (
            <span className="rounded-full bg-royal-blue px-2 py-0.5 text-xs text-white">
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
  variant?: 'default' | 'critical'
}

function StatBox({ label, value, variant = 'default' }: StatBoxProps) {
  return (
    <div className="rounded-lg bg-bg-elevated-dark p-2">
      <div
        className={cn(
          'text-lg font-bold',
          variant === 'critical' ? 'text-critical' : 'text-text-primary-dark'
        )}
      >
        {value}
      </div>
      <div className="text-xs text-text-muted-dark">{label}</div>
    </div>
  )
}
