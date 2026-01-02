// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Main Layout Component
// Enterprise layout with sidebar, header, console
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { cn } from '@/lib/utils'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { GlobalConsole } from './GlobalConsole'
import { ToastContainer } from '@/components/ui/Toast'
import { useEventStore } from '@/stores/eventStore'

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { isSidebarCollapsed, isConsoleExpanded } = useEventStore()
  
  return (
    <div className="min-h-screen bg-bg-dark">
      {/* Sidebar */}
      <Sidebar />
      
      {/* Header */}
      <Header />
      
      {/* Main Content Area */}
      <main
        className={cn(
          'pt-16 transition-all duration-300 ease-in-out',
          isSidebarCollapsed ? 'ml-16' : 'ml-64',
          isConsoleExpanded ? 'pb-64' : 'pb-10'
        )}
      >
        <div className="p-6">{children}</div>
      </main>
      
      {/* Global Console */}
      <GlobalConsole />
      
      {/* Toast Notifications */}
      <ToastContainer />
    </div>
  )
}
