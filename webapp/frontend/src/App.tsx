// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Main Application
// Enterprise-Grade SaaS Frontend
// ═══════════════════════════════════════════════════════════════

import { useEffect } from 'react'
import { Layout } from '@/components/layout/Layout'
import { AIAssistantSidebar } from '@/components/ai/AIAssistantSidebar'
import { Dashboard } from '@/pages/Dashboard'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useEventStore } from '@/stores/eventStore'

function App() {
  // Initialize WebSocket connection
  const { isConnected } = useWebSocket({ autoConnect: true })
  
  // Demo: Add some sample data when connected (remove in production)
  const { addLog, addActivity } = useEventStore()
  
  useEffect(() => {
    if (isConnected) {
      // Add a welcome log
      addLog({
        id: 'welcome-log',
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'Connected to RAGLOX v3.0 backend. WebSocket established.',
        specialist: 'System',
      })
      
      addActivity({
        type: 'status_change',
        title: 'System Ready',
        description: 'Connected to RAGLOX backend. Ready for operations.',
        timestamp: new Date().toISOString(),
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
