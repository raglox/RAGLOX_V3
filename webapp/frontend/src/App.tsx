// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Main Application
// Enterprise-Grade SaaS Frontend
// ═══════════════════════════════════════════════════════════════

import { useEffect, useRef } from 'react'
import { Layout } from '@/components/layout/Layout'
import { AIAssistantSidebar } from '@/components/ai/AIAssistantSidebar'
import { Dashboard } from '@/pages/Dashboard'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useEventStore } from '@/stores/eventStore'

function App() {
  // Initialize WebSocket connection
  const { isConnected } = useWebSocket({ autoConnect: true })
  
  // Track if welcome message was already shown
  const welcomeShownRef = useRef(false)
  
  // Demo: Add some sample data when connected (remove in production)
  const { addLog, addActivity } = useEventStore()
  
  useEffect(() => {
    // Only show welcome message once per session
    if (isConnected && !welcomeShownRef.current) {
      welcomeShownRef.current = true
      
      // Add a welcome log with unique ID based on timestamp
      const timestamp = new Date().toISOString()
      addLog({
        id: `welcome-log-${Date.now()}`,
        timestamp,
        level: 'info',
        message: 'Connected to RAGLOX v3.0 backend. WebSocket established.',
        specialist: 'System',
      })
      
      addActivity({
        type: 'status_change',
        title: 'System Ready',
        description: 'Connected to RAGLOX backend. Ready for operations.',
        timestamp,
      })
    }
  }, [isConnected, addLog, addActivity])
  
  return (
    <>
      <Layout>
        <Dashboard />
      </Layout>
      
      {/* AI Assistant Sidebar (renders conditionally based on state) */}
      <AIAssistantSidebar />
    </>
  )
}

export default App
