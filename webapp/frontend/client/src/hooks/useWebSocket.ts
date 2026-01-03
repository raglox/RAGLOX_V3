// RAGLOX v3.0 - WebSocket Hook
// Dedicated hook for real-time WebSocket connections with the backend

import { useState, useEffect, useCallback, useRef } from "react";
import type {
  WebSocketMessage,
  WebSocketEventType,
  EventCard,
  PlanTask,
  Target,
  Vulnerability,
  Credential,
  Session,
  ApprovalRequest,
  ChatMessage,
} from "@/types";

// WebSocket Base URL - configurable via environment
const getWsBaseUrl = (): string | null => {
  const envUrl = import.meta.env.VITE_WS_URL;
  if (envUrl) return envUrl;
  
  // In development/testing, allow ws:// even from HTTPS pages
  // Modern browsers support mixed content for WebSocket in some cases
  // The connection will fail gracefully if blocked, and we'll fall back to polling
  
  // Check if we're in a development environment
  const isDev = import.meta.env.DEV || 
                import.meta.env.MODE === 'development' ||
                (typeof window !== 'undefined' && (
                  window.location.hostname === 'localhost' ||
                  window.location.hostname.includes('genspark') ||
                  window.location.hostname.includes('sandbox') ||
                  window.location.hostname.includes('e2b.dev')
                ));
  
  // For sandbox/development environments, always try ws://
  // It may fail, but that's handled by our fallback mechanism
  if (isDev) {
    console.log('[WebSocket] Development mode detected - attempting ws:// connection');
    return "ws://172.245.232.188:8000";
  }
  
  // For production HTTPS, we need wss:// - return null to disable WebSocket
  if (typeof window !== 'undefined' && window.location.protocol === 'https:') {
    console.log('[WebSocket] Production HTTPS detected - WebSocket disabled (backend needs wss://)');
    return null;
  }
  
  return "ws://172.245.232.188:8000";
};

const WS_BASE_URL = getWsBaseUrl();

// ============================================
// WebSocket Connection State
// ============================================

export type ConnectionStatus = "connecting" | "connected" | "disconnected" | "error" | "disabled" | "polling";

interface UseWebSocketOptions {
  autoReconnect?: boolean;
  maxReconnectAttempts?: number;
  reconnectDelay?: number;
  onMessage?: (message: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
}

interface UseWebSocketResult {
  // Connection state
  status: ConnectionStatus;
  isConnected: boolean;
  isPolling: boolean;
  lastMessage: WebSocketMessage | null;
  
  // Parsed data
  events: EventCard[];
  planTasks: PlanTask[];
  terminalOutput: string[];
  
  // New data from WebSocket
  newTargets: Target[];
  newVulnerabilities: Vulnerability[];
  newCredentials: Credential[];
  newSessions: Session[];
  newApprovals: ApprovalRequest[];
  newChatMessages: ChatMessage[];
  
  // Actions
  connect: () => void;
  disconnect: () => void;
  send: (data: unknown) => void;
  clearEvents: () => void;
  clearTerminal: () => void;
  startPolling: () => void;
  stopPolling: () => void;
}

// ============================================
// useWebSocket Hook
// ============================================

export function useWebSocket(
  missionId: string,
  options: UseWebSocketOptions = {}
): UseWebSocketResult {
  const {
    autoReconnect = true,
    maxReconnectAttempts = 3, // Reduced from 5 - fail faster if server doesn't support WS
    reconnectDelay = 2000,    // Increased initial delay
    onMessage,
    onConnect,
    onDisconnect,
    onError,
  } = options;

  // Connection state
  const [status, setStatus] = useState<ConnectionStatus>(
    WS_BASE_URL ? "disconnected" : "disabled"
  );
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  
  // Parsed data
  const [events, setEvents] = useState<EventCard[]>([]);
  const [planTasks, setPlanTasks] = useState<PlanTask[]>([]);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  
  // New data arrays
  const [newTargets, setNewTargets] = useState<Target[]>([]);
  const [newVulnerabilities, setNewVulnerabilities] = useState<Vulnerability[]>([]);
  const [newCredentials, setNewCredentials] = useState<Credential[]>([]);
  const [newSessions, setNewSessions] = useState<Session[]>([]);
  const [newApprovals, setNewApprovals] = useState<ApprovalRequest[]>([]);
  const [newChatMessages, setNewChatMessages] = useState<ChatMessage[]>([]);

  // Refs
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // ============================================
  // Message Handler
  // ============================================
  
  const handleMessage = useCallback((message: WebSocketMessage) => {
    setLastMessage(message);
    onMessage?.(message);

    const { type, data, timestamp } = message;

    // Create event card
    const eventCard: EventCard = {
      id: `event-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      title: getEventTitle(type, data),
      description: getEventDescription(type, data),
      timestamp,
      data,
      expanded: false,
    };

    // Handle specific event types
    switch (type) {
      case "connected":
        console.log("[WebSocket] Connected to mission:", missionId);
        break;

      case "new_target":
        setNewTargets((prev) => [...prev, data as Target]);
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "target_update":
        setNewTargets((prev) => {
          const target = data as Target;
          const index = prev.findIndex((t) => t.target_id === target.target_id);
          if (index >= 0) {
            const updated = [...prev];
            updated[index] = target;
            return updated;
          }
          return prev;
        });
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "new_vuln":
        setNewVulnerabilities((prev) => [...prev, data as Vulnerability]);
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "new_cred":
        setNewCredentials((prev) => [...prev, data as Credential]);
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "new_session":
        setNewSessions((prev) => [...prev, data as Session]);
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "approval_request":
        setNewApprovals((prev) => [...prev, data as ApprovalRequest]);
        // Create approval-specific event card
        const approvalCard: EventCard = {
          ...eventCard,
          type: "approval_request",
          approval: data as ApprovalRequest,
        };
        setEvents((prev) => [approvalCard, ...prev].slice(0, 100));
        break;

      case "approval_resolved":
        setNewApprovals((prev) =>
          prev.filter((a) => a.action_id !== (data as { action_id: string }).action_id)
        );
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "chat_message":
        setNewChatMessages((prev) => [...prev, data as ChatMessage]);
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "ai_plan":
        // Handle AI plan data
        const aiPlanCard: EventCard = {
          ...eventCard,
          type: "ai_plan",
          aiPlan: data as EventCard["aiPlan"],
        };
        setEvents((prev) => [aiPlanCard, ...prev].slice(0, 100));
        
        // Update plan tasks if included
        if ((data as { tasks?: PlanTask[] }).tasks) {
          setPlanTasks((data as { tasks: PlanTask[] }).tasks);
        }
        break;

      case "mission_status":
      case "status_change":
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "goal_achieved":
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      case "statistics":
        // Statistics updates don't need to create events
        break;

      case "error":
        console.error("[WebSocket] Server error:", data);
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        break;

      default:
        // Generic event handling
        setEvents((prev) => [eventCard, ...prev].slice(0, 100));
        
        // Check for terminal output
        if ((data as { output?: string }).output) {
          const output = (data as { output: string }).output;
          setTerminalOutput((prev) => [...prev, ...output.split('\n')]);
        }
        if ((data as { command?: string }).command) {
          const command = (data as { command: string }).command;
          setTerminalOutput((prev) => [...prev, `$ ${command}`]);
        }
    }
  }, [missionId, onMessage]);

  // ============================================
  // Connection Management
  // ============================================

  const connect = useCallback(() => {
    // Check if WebSocket is disabled
    if (!WS_BASE_URL) {
      console.log("[WebSocket] WebSocket disabled - running in demo mode");
      setStatus("disabled");
      return;
    }

    // Don't connect if already connected or connecting
    if (wsRef.current?.readyState === WebSocket.OPEN ||
        wsRef.current?.readyState === WebSocket.CONNECTING) {
      return;
    }

    const url = `${WS_BASE_URL}/ws/missions/${missionId}`;
    console.log("[WebSocket] Connecting to:", url);
    setStatus("connecting");

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log("[WebSocket] Connected successfully");
        setStatus("connected");
        reconnectAttemptsRef.current = 0;
        onConnect?.();
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as WebSocketMessage;
          handleMessage(message);
        } catch (e) {
          console.error("[WebSocket] Failed to parse message:", e);
        }
      };

      ws.onerror = (error) => {
        console.warn("[WebSocket] Connection error - server may not support WebSocket");
        // Don't set status to error immediately - let onclose handle it
        onError?.(error);
      };

      ws.onclose = (event) => {
        console.log("[WebSocket] Connection closed", event.code, event.reason);
        wsRef.current = null;
        onDisconnect?.();

        // If we got a 404 response (code 1006 with no prior connection), the endpoint doesn't exist
        // Switch to disabled mode instead of retrying
        if (reconnectAttemptsRef.current >= maxReconnectAttempts - 1) {
          console.log("[WebSocket] Max reconnect attempts reached - switching to demo mode");
          setStatus("disabled");
          return;
        }

        // Attempt reconnection only if auto-reconnect is enabled
        if (autoReconnect && reconnectAttemptsRef.current < maxReconnectAttempts) {
          setStatus("disconnected");
          reconnectAttemptsRef.current++;
          const delay = reconnectDelay * Math.pow(2, reconnectAttemptsRef.current - 1);
          console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts})`);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, delay);
        } else {
          setStatus("disabled");
        }
      };
    } catch (error) {
      console.error("[WebSocket] Failed to connect:", error);
      setStatus("error");
    }
  }, [
    missionId,
    autoReconnect,
    maxReconnectAttempts,
    reconnectDelay,
    handleMessage,
    onConnect,
    onDisconnect,
    onError,
  ]);

  const disconnect = useCallback(() => {
    // Clear reconnect timeout
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    // Close WebSocket
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus("disconnected");
    reconnectAttemptsRef.current = 0;
  }, []);

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    } else {
      console.warn("[WebSocket] Cannot send - not connected");
    }
  }, []);

  // ============================================
  // Utility Functions
  // ============================================

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const clearTerminal = useCallback(() => {
    setTerminalOutput([]);
  }, []);

  // ============================================
  // Polling Functions (Fallback for when WebSocket fails)
  // ============================================

  const API_BASE_URL = import.meta.env.VITE_API_URL || "http://172.245.232.188:8000";
  const POLLING_INTERVAL = 5000; // 5 seconds

  const fetchData = useCallback(async () => {
    try {
      // Fetch stats
      const statsResponse = await fetch(`${API_BASE_URL}/api/v1/missions/${missionId}/stats`);
      if (statsResponse.ok) {
        const stats = await statsResponse.json();
        handleMessage({
          type: "statistics",
          data: stats,
          timestamp: new Date().toISOString(),
        });
      }

      // Fetch approvals
      const approvalsResponse = await fetch(`${API_BASE_URL}/api/v1/missions/${missionId}/approvals`);
      if (approvalsResponse.ok) {
        const approvals = await approvalsResponse.json();
        if (Array.isArray(approvals) && approvals.length > 0) {
          approvals.forEach((approval: ApprovalRequest) => {
            handleMessage({
              type: "approval_request",
              data: approval,
              timestamp: new Date().toISOString(),
            });
          });
        }
      }

      // Fetch chat messages (latest 10)
      const chatResponse = await fetch(`${API_BASE_URL}/api/v1/missions/${missionId}/chat?limit=10`);
      if (chatResponse.ok) {
        const messages = await chatResponse.json();
        if (Array.isArray(messages) && messages.length > 0) {
          messages.forEach((msg: ChatMessage) => {
            handleMessage({
              type: "chat_message",
              data: msg,
              timestamp: msg.timestamp || new Date().toISOString(),
            });
          });
        }
      }
    } catch (error) {
      console.log("[Polling] Fetch error (mission may not exist):", error);
    }
  }, [missionId, handleMessage]);

  const startPolling = useCallback(() => {
    if (pollingIntervalRef.current) return; // Already polling

    console.log("[Polling] Starting polling mode (WebSocket unavailable)");
    setStatus("polling");
    setIsPolling(true);

    // Initial fetch
    fetchData();

    // Start interval
    pollingIntervalRef.current = setInterval(fetchData, POLLING_INTERVAL);
  }, [fetchData]);

  const stopPolling = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
    setIsPolling(false);
  }, []);

  // ============================================
  // Effect: Auto-connect on mount
  // ============================================

  useEffect(() => {
    if (missionId && WS_BASE_URL) {
      connect();
    } else if (missionId && !WS_BASE_URL) {
      // WebSocket not available, start polling
      startPolling();
    }

    return () => {
      disconnect();
      stopPolling();
    };
  }, [missionId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-start polling when WebSocket is disabled
  useEffect(() => {
    if (status === "disabled" && missionId && !isPolling) {
      console.log("[WebSocket] Switching to polling mode");
      startPolling();
    }
  }, [status, missionId, isPolling, startPolling]);

  return {
    status,
    isConnected: status === "connected",
    isPolling,
    lastMessage,
    events,
    planTasks,
    terminalOutput,
    newTargets,
    newVulnerabilities,
    newCredentials,
    newSessions,
    newApprovals,
    newChatMessages,
    connect,
    disconnect,
    send,
    clearEvents,
    clearTerminal,
    startPolling,
    stopPolling,
  };
}

// ============================================
// Helper Functions
// ============================================

function getEventTitle(type: WebSocketEventType | string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case "connected":
      return "Connected to Mission";
    case "new_target":
      return `Target Discovered: ${d.ip || d.hostname || "Unknown"}`;
    case "target_update":
      return `Target Updated: ${d.ip || d.hostname || "Unknown"}`;
    case "new_vuln":
      return `Vulnerability Found: ${d.name || d.type || "Unknown"}`;
    case "new_cred":
      return `Credential Harvested: ${d.username || "Unknown"}`;
    case "new_session":
      return `Session Established: ${d.type || "Unknown"}`;
    case "approval_request":
      return `Approval Required: ${d.action_type || "Action"}`;
    case "approval_resolved":
      return `Approval Resolved`;
    case "mission_status":
    case "status_change":
      return `Mission Status: ${d.status || "Updated"}`;
    case "statistics":
      return "Statistics Updated";
    case "goal_achieved":
      return `Goal Achieved: ${d.goal || d.description || "Goal"}`;
    case "chat_message":
      return `Message from ${d.role || "System"}`;
    case "ai_plan":
      return `AI Planning: ${d.message || "Task"}`;
    case "error":
      return `Error: ${d.message || "Unknown error"}`;
    default:
      return `Event: ${type}`;
  }
}

function getEventDescription(type: WebSocketEventType | string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case "new_target":
      return `Discovered ${d.os || "Unknown OS"} at ${d.ip || d.hostname || "Unknown"}`;
    case "new_vuln":
      return `${d.severity || "Unknown"} severity${d.cvss ? ` - CVSS: ${d.cvss}` : ""}`;
    case "new_cred":
      return `${d.type || "Unknown"} credential for ${d.username || "Unknown"}`;
    case "new_session":
      return `${d.type || "Unknown"} session as ${d.user || d.username || "Unknown"}`;
    case "approval_request":
      return (d.action_description as string) || "Action requires approval";
    case "chat_message":
      return (d.content as string) || "";
    case "ai_plan":
      return (d.reasoning as string) || (d.message as string) || "";
    default:
      return "";
  }
}

// ============================================
// Export Default
// ============================================

export default useWebSocket;
