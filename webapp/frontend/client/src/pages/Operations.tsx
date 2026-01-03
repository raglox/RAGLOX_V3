// RAGLOX v3.0 - Operations Page (Manus-style)
// Full-screen operations interface with Sidebar, Chat, and Terminal
// Updated for real-time WebSocket integration with polling fallback
// Enhanced with better error handling and user feedback

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams } from "wouter";
import { DualPanelLayout } from "@/components/manus";
import { useMissionStore } from "@/stores/missionStore";
import { useWebSocket } from "@/hooks/useWebSocket";
import { hitlApi, chatApi, missionApi, ApiError } from "@/lib/api";
import type { ChatMessage, EventCard, PlanTask } from "@/types";
import { toast } from "sonner";

// Default Mission ID for testing - can be configured via environment variable
const DEFAULT_MISSION_ID = import.meta.env.VITE_DEFAULT_MISSION_ID || "5bae06db-0f6c-478d-81a3-b54e2f3eb9d5";

// Polling interval when WebSocket is unavailable (in ms)
const POLLING_INTERVAL = 5000;

export default function Operations() {
  const params = useParams<{ missionId?: string }>();
  const missionId = params.missionId || DEFAULT_MISSION_ID;

  // Zustand store for mission data
  const {
    mission,
    targets,
    vulnerabilities,
    credentials,
    sessions,
    chatMessages: storeChatMessages,
    isLoading,
    loadAllData,
    addEvent,
  } = useMissionStore();

  // WebSocket hook for real-time updates
  const {
    status: wsStatus,
    isConnected,
    events: wsEvents,
    planTasks: wsPlanTasks,
    terminalOutput: wsTerminalOutput,
    newApprovals,
    newChatMessages,
    clearEvents,
    clearTerminal,
  } = useWebSocket(missionId, {
    onConnect: () => {
      toast.success("Connected to mission (real-time)");
    },
    onDisconnect: () => {
      // Don't show toast on every disconnect - only on final failure
    },
    onError: () => {
      // Error handled in onclose
    },
  });
  
  // Track if we've shown the fallback notification
  const shownFallbackNotification = useRef(false);
  
  // Polling interval ref
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Local state for terminal output (combining initial + WebSocket)
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [events, setEvents] = useState<EventCard[]>([]);
  const [planTasks, setPlanTasks] = useState<PlanTask[]>([]);

  // Load mission data on mount
  useEffect(() => {
    if (missionId) {
      loadAllData(missionId).catch((error) => {
        console.error("[Operations] Failed to load mission data:", error);
        // Don't show error toast if mission doesn't exist - it's expected for test mission
        if (!String(error).includes("404")) {
          toast.error("Failed to load mission data");
        }
      });
    }
  }, [missionId, loadAllData]);
  
  // Fallback polling when WebSocket is disabled
  useEffect(() => {
    // If WebSocket is disabled, start polling
    if (wsStatus === "disabled") {
      if (!shownFallbackNotification.current) {
        shownFallbackNotification.current = true;
        toast.info("Using polling mode (WebSocket unavailable)", {
          duration: 3000,
        });
      }
      
      // Start polling
      const poll = async () => {
        try {
          // Fetch latest data
          const [stats, approvals, chat] = await Promise.allSettled([
            missionApi.stats(missionId).catch(() => null),
            hitlApi.list(missionId).catch(() => []),
            chatApi.list(missionId, 10).catch(() => []),
          ]);
          
          // Update approvals if we got new ones
          if (approvals.status === "fulfilled" && Array.isArray(approvals.value)) {
            // Could update local state here
          }
          
          // Update chat messages
          if (chat.status === "fulfilled" && Array.isArray(chat.value)) {
            setChatMessages((prev) => {
              const existingIds = new Set(prev.map((m) => m.id));
              const newMsgs = chat.value.filter((m: ChatMessage) => !existingIds.has(m.id));
              if (newMsgs.length > 0) {
                return [...prev, ...newMsgs];
              }
              return prev;
            });
          }
        } catch (error) {
          console.error("[Polling] Error:", error);
        }
      };
      
      // Initial poll
      poll();
      
      // Set up interval
      pollingIntervalRef.current = setInterval(poll, POLLING_INTERVAL);
      
      return () => {
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }
      };
    }
    
    // Clear polling if WebSocket becomes available
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    };
  }, [wsStatus, missionId]);

  // Update local state from WebSocket
  useEffect(() => {
    if (wsEvents.length > 0) {
      setEvents((prev) => {
        // Merge new events, avoiding duplicates
        const existingIds = new Set(prev.map((e) => e.id));
        const newEvents = wsEvents.filter((e) => !existingIds.has(e.id));
        return [...newEvents, ...prev].slice(0, 100);
      });
    }
  }, [wsEvents]);

  useEffect(() => {
    if (wsPlanTasks.length > 0) {
      setPlanTasks(wsPlanTasks);
    }
  }, [wsPlanTasks]);

  useEffect(() => {
    if (wsTerminalOutput.length > 0) {
      setTerminalOutput((prev) => [...prev, ...wsTerminalOutput]);
    }
  }, [wsTerminalOutput]);

  useEffect(() => {
    if (newChatMessages.length > 0) {
      setChatMessages((prev) => {
        const existingIds = new Set(prev.map((m) => m.id));
        const newMsgs = newChatMessages.filter((m) => !existingIds.has(m.id));
        return [...prev, ...newMsgs];
      });
    }
  }, [newChatMessages]);

  // Sync store chat messages
  useEffect(() => {
    if (storeChatMessages.length > 0) {
      setChatMessages(storeChatMessages);
    }
  }, [storeChatMessages]);

  // Handle sending messages with enhanced error handling
  const handleSendMessage = useCallback(async (content: string) => {
    // Add user message to local state immediately (optimistic update)
    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: "user",
      content,
      timestamp: new Date().toISOString(),
    };
    setChatMessages((prev) => [...prev, userMessage]);

    // Try to send via API
    try {
      const response = await chatApi.send(missionId, content);
      
      // Add AI response to chat
      setChatMessages((prev) => [...prev, response]);
      
      // Add to events for activity feed
      addEvent({
        id: `event-${Date.now()}`,
        type: "chat_message",
        title: "Message from assistant",
        description: response.content,
        timestamp: response.timestamp,
        status: "completed",
        data: response,
        expanded: false,
      });
    } catch (error) {
      console.error("[Operations] Failed to send message:", error);
      
      // Create helpful error message based on error type
      let errorMessage = "Failed to send message";
      let errorDescription = "Unknown error occurred";
      
      if (error instanceof ApiError) {
        if (error.status === 404) {
          errorMessage = "Mission not found";
          errorDescription = "The mission may have been deleted or doesn't exist.";
        } else if (error.status === 0) {
          errorMessage = "Connection failed";
          errorDescription = "Unable to connect to backend server. Check if the server is running.";
        } else if (error.status === 503) {
          errorMessage = "Service unavailable";
          errorDescription = "The backend service is temporarily unavailable.";
        } else {
          errorDescription = error.message;
        }
      } else if (error instanceof Error) {
        errorDescription = error.message;
      }
      
      // Add system response indicating error
      const errorResponse: ChatMessage = {
        id: `msg-error-${Date.now()}`,
        role: "system",
        content: `⚠️ ${errorMessage}: ${errorDescription}`,
        timestamp: new Date().toISOString(),
      };
      setChatMessages((prev) => [...prev, errorResponse]);
      
      // Show toast notification
      toast.error(errorMessage, {
        description: errorDescription,
      });
    }
  }, [missionId, addEvent]);

  // Handle command click (show in terminal)
  const handleCommandClick = useCallback((command: string) => {
    setTerminalOutput((prev) => [
      ...prev,
      "",
      `ubuntu@raglox:~ $ ${command}`,
      "Executing command...",
    ]);
  }, []);

  // Handle approval with enhanced feedback
  const handleApprove = useCallback(async (actionId: string, comment?: string) => {
    try {
      const response = await hitlApi.approve(missionId, actionId, comment);
      
      // Show success message
      toast.success("Action approved", {
        description: "The command is now executing.",
      });
      
      // Remove from events
      setEvents((prev) => prev.filter(
        (e) => e.type !== "approval_request" || e.approval?.action_id !== actionId
      ));
      
      // Add approval confirmation event
      addEvent({
        id: `event-approved-${Date.now()}`,
        type: "approval_resolved",
        title: "Action Approved",
        description: `Action ${actionId} approved${comment ? `: ${comment}` : ""}`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });
    } catch (error) {
      console.error("[Operations] Failed to approve action:", error);
      
      let errorMessage = "Failed to approve action";
      if (error instanceof ApiError) {
        errorMessage = error.message;
      }
      
      toast.error("Approval failed", {
        description: errorMessage,
      });
    }
  }, [missionId, addEvent]);

  // Handle rejection with enhanced feedback
  const handleReject = useCallback(async (actionId: string, reason?: string, comment?: string) => {
    try {
      await hitlApi.reject(missionId, actionId, reason || "User rejected", comment);
      
      // Show success message
      toast.info("Action rejected", {
        description: "The system will seek alternative approaches.",
      });
      
      // Remove from events
      setEvents((prev) => prev.filter(
        (e) => e.type !== "approval_request" || e.approval?.action_id !== actionId
      ));
      
      // Add rejection confirmation event
      addEvent({
        id: `event-rejected-${Date.now()}`,
        type: "approval_resolved",
        title: "Action Rejected",
        description: `Action ${actionId} rejected: ${reason || "User decision"}`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });
    } catch (error) {
      console.error("[Operations] Failed to reject action:", error);
      
      let errorMessage = "Failed to reject action";
      if (error instanceof ApiError) {
        errorMessage = error.message;
      }
      
      toast.error("Rejection failed", {
        description: errorMessage,
      });
    }
  }, [missionId, addEvent]);

  // Handle terminal clear
  const handleClearTerminal = useCallback(() => {
    setTerminalOutput([]);
    clearTerminal();
  }, [clearTerminal]);

  return (
    <div className="h-screen w-screen overflow-hidden bg-background">
      <DualPanelLayout
        messages={chatMessages}
        events={events}
        planTasks={planTasks}
        onSendMessage={handleSendMessage}
        isConnected={isConnected}
        connectionStatus={wsStatus}
        terminalOutput={terminalOutput}
        terminalTitle="Target Terminal"
        terminalSubtitle="RAGLOX is using Terminal"
        executingCommand={terminalOutput.length > 0 ? terminalOutput[terminalOutput.length - 1]?.replace(/^.*\$ /, '') : undefined}
        isTerminalLive={isConnected}
        terminalProgress={planTasks.length > 0 ? (planTasks.filter(t => t.status === "completed").length / planTasks.length) * 100 : 0}
        terminalTotalSteps={planTasks.length}
        terminalCurrentStep={planTasks.filter(t => t.status === "completed").length}
        terminalCurrentTask={planTasks.find(t => t.status === "running")?.title || planTasks.find(t => t.status === "pending")?.title}
        terminalTaskCompleted={planTasks.length > 0 && planTasks.every(t => t.status === "completed")}
        onCommandClick={handleCommandClick}
        onApprove={handleApprove}
        onReject={handleReject}
        onClearTerminal={handleClearTerminal}
        showSidebar={true}
        showDemoData={false}
      />
    </div>
  );
}
