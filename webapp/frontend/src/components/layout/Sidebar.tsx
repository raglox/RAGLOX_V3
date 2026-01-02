// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Sidebar Component
// Ultra-minimal, icon-only sidebar that expands on hover
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  LayoutDashboard,
  Target,
  Brain,
  Settings,
  Shield,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'

interface NavItem {
  icon: React.ElementType
  label: string
  href: string
}

const navItems: NavItem[] = [
  { icon: LayoutDashboard, label: 'Dashboard', href: '/' },
  { icon: Target, label: 'Targets', href: '/targets' },
  { icon: Brain, label: 'Intelligence', href: '/intelligence' },
  { icon: Settings, label: 'Settings', href: '/settings' },
]

export function Sidebar() {
  const [isHovered, setIsHovered] = React.useState(false)
  const { isSidebarCollapsed, setSidebarCollapsed } = useEventStore()
  
  // Determine if sidebar should be expanded
  const isExpanded = !isSidebarCollapsed || isHovered
  
  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 h-screen',
        'flex flex-col transition-all duration-300 ease-out',
        'glass border-r border-white/5',
        isExpanded ? 'w-56' : 'w-[72px]'
      )}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* Logo Section */}
      <div className="flex h-16 items-center px-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-royal-blue to-royal-blue-dark shadow-lg shadow-royal-blue/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div className={cn(
            'flex flex-col transition-all duration-300 overflow-hidden',
            isExpanded ? 'opacity-100 w-auto' : 'opacity-0 w-0'
          )}>
            <span className="text-base font-semibold text-text-primary-dark tracking-tight whitespace-nowrap">RAGLOX</span>
            <span className="text-[10px] text-text-muted-dark font-mono whitespace-nowrap">v3.0</span>
          </div>
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 px-3 py-6 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.href}
            item={item}
            isExpanded={isExpanded}
          />
        ))}
      </nav>
      
      {/* Pin Toggle (only visible when hovered) */}
      {isHovered && (
        <div className="px-3 pb-4">
          <button
            onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
            className={cn(
              'w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium',
              'text-text-muted-dark hover:text-text-primary-dark',
              'hover:bg-white/5 transition-all duration-200'
            )}
          >
            <div className={cn(
              'w-3 h-3 rounded-full border-2 transition-colors',
              isSidebarCollapsed 
                ? 'border-text-muted-dark' 
                : 'border-royal-blue bg-royal-blue'
            )} />
            <span className={cn(
              'transition-opacity duration-200',
              isExpanded ? 'opacity-100' : 'opacity-0'
            )}>
              {isSidebarCollapsed ? 'Pin sidebar' : 'Pinned'}
            </span>
          </button>
        </div>
      )}
    </aside>
  )
}

// Navigation Link Component
interface NavLinkProps {
  item: NavItem
  isExpanded: boolean
}

function NavLink({ item, isExpanded }: NavLinkProps) {
  const Icon = item.icon
  const isActive = window.location.pathname === item.href
  
  return (
    <a
      href={item.href}
      className={cn(
        'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium',
        'transition-all duration-200 group',
        isActive
          ? 'bg-royal-blue/10 text-royal-blue'
          : 'text-text-secondary-dark hover:text-text-primary-dark hover:bg-white/5'
      )}
      title={!isExpanded ? item.label : undefined}
    >
      <Icon className={cn(
        'h-5 w-5 flex-shrink-0 transition-transform duration-200',
        !isActive && 'group-hover:scale-110'
      )} />
      <span className={cn(
        'whitespace-nowrap transition-all duration-300 overflow-hidden',
        isExpanded ? 'opacity-100 w-auto' : 'opacity-0 w-0'
      )}>
        {item.label}
      </span>
      {isActive && (
        <div className={cn(
          'ml-auto w-1.5 h-1.5 rounded-full bg-royal-blue transition-opacity',
          isExpanded ? 'opacity-100' : 'opacity-0'
        )} />
      )}
    </a>
  )
}
