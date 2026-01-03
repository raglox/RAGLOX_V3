// RAGLOX v3.0 - Mission Store (Zustand)
// Centralized state management for mission data

import { create } from "zustand";
import type {
  Mission,
  Target,
  Vulnerability,
  Credential,
  Session,
  ApprovalRequest,
  ChatMessage,
  EventCard,
  PlanTask,
  WebSocketMessage,
  TaskStatus,
} from "@/types";
import { missionApi, targetApi, vulnApi, credApi, sessionApi, hitlApi, chatApi, MissionWebSocket } from "@/lib/api";

interface MissionState {
  // Current mission
  currentMissionId: string | null;
  mission: Mission | null;
  
  // Data
  targets: Target[];
  vulnerabilities: Vulnerability[];
  credentials: Credential[];
  sessions: Session[];
  approvals: ApprovalRequest[];
  chatMessages: ChatMessage[];
  
  // UI State
  events: EventCard[];
  planTasks: PlanTask[];
  isLoading: boolean;
  error: string | null;
  
  // WebSocket
  wsConnection: MissionWebSocket | null;
  isConnected: boolean;
  
  // Actions
  setMissionId: (id: string | null) => void;
  loadMission: (id: string) => Promise<void>;
  loadAllData: (id: string) => Promise<void>;
  
  // WebSocket Actions
  connectWebSocket: (missionId: string) => void;
  disconnectWebSocket: () => void;
  handleWebSocketMessage: (message: WebSocketMessage) => void;
  
  // Chat Actions
  sendMessage: (content: string) => Promise<void>;
  
  // HITL Actions
  approveAction: (actionId: string, comment?: string) => Promise<void>;
  rejectAction: (actionId: string, reason: string, comment?: string) => Promise<void>;
  
  // Event Actions
  addEvent: (event: EventCard) => void;
  toggleEventExpanded: (eventId: string) => void;
  
  // Plan Actions
  updateTaskStatus: (taskId: string, status: TaskStatus) => void;
  
  // Utility
  clearError: () => void;
  reset: () => void;
}

const initialState = {
  currentMissionId: null,
  mission: null,
  targets: [],
  vulnerabilities: [],
  credentials: [],
  sessions: [],
  approvals: [],
  chatMessages: [],
  events: [],
  planTasks: [],
  isLoading: false,
  error: null,
  wsConnection: null,
  isConnected: false,
};

export const useMissionStore = create<MissionState>((set, get) => ({
  ...initialState,

  setMissionId: (id) => set({ currentMissionId: id }),

  loadMission: async (id) => {
    set({ isLoading: true, error: null });
    try {
      const mission = await missionApi.get(id);
      set({ mission, currentMissionId: id });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ isLoading: false });
    }
  },

  loadAllData: async (id) => {
    set({ isLoading: true, error: null });
    try {
      const [mission, targets, vulnerabilities, credentials, sessions, approvals, chatMessages] = 
        await Promise.all([
          missionApi.get(id),
          targetApi.list(id).catch(() => []),
          vulnApi.list(id).catch(() => []),
          credApi.list(id).catch(() => []),
          sessionApi.list(id).catch(() => []),
          hitlApi.list(id).catch(() => []),
          chatApi.list(id).catch(() => []),
        ]);
      
      set({
        mission,
        currentMissionId: id,
        targets,
        vulnerabilities,
        credentials,
        sessions,
        approvals,
        chatMessages,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ isLoading: false });
    }
  },

  connectWebSocket: (missionId) => {
    const { wsConnection } = get();
    
    // Disconnect existing connection
    if (wsConnection) {
      wsConnection.disconnect();
    }

    const ws = new MissionWebSocket(
      missionId,
      (message) => get().handleWebSocketMessage(message as WebSocketMessage),
      () => set({ isConnected: false }),
      () => set({ isConnected: false })
    );

    ws.connect();
    set({ wsConnection: ws, isConnected: true });
  },

  disconnectWebSocket: () => {
    const { wsConnection } = get();
    if (wsConnection) {
      wsConnection.disconnect();
    }
    set({ wsConnection: null, isConnected: false });
  },

  handleWebSocketMessage: (message) => {
    const { type, data, timestamp } = message;

    // Create event card for the message
    const eventCard: EventCard = {
      id: `event-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type,
      title: getEventTitle(type, data),
      description: getEventDescription(type, data),
      timestamp,
      data,
      expanded: false,
    };

    // Add to events
    set((state) => ({
      events: [eventCard, ...state.events].slice(0, 100), // Keep last 100 events
    }));

    // Handle specific event types
    switch (type) {
      case "new_target":
        set((state) => ({
          targets: [...state.targets, data as Target],
        }));
        break;

      case "target_update":
        set((state) => ({
          targets: state.targets.map((t) =>
            t.target_id === (data as Target).target_id ? (data as Target) : t
          ),
        }));
        break;

      case "new_vuln":
        set((state) => ({
          vulnerabilities: [...state.vulnerabilities, data as Vulnerability],
        }));
        break;

      case "new_cred":
        set((state) => ({
          credentials: [...state.credentials, data as Credential],
        }));
        break;

      case "new_session":
        set((state) => ({
          sessions: [...state.sessions, data as Session],
        }));
        break;

      case "approval_request":
        set((state) => ({
          approvals: [...state.approvals, data as ApprovalRequest],
        }));
        break;

      case "approval_resolved":
        set((state) => ({
          approvals: state.approvals.filter(
            (a) => a.action_id !== (data as { action_id: string }).action_id
          ),
        }));
        break;

      case "chat_message":
        set((state) => ({
          chatMessages: [...state.chatMessages, data as ChatMessage],
        }));
        break;

      case "mission_status":
        set((state) => ({
          mission: state.mission
            ? { ...state.mission, status: (data as { status: string }).status as Mission["status"] }
            : null,
        }));
        break;
    }
  },

  sendMessage: async (content) => {
    const { currentMissionId } = get();
    if (!currentMissionId) return;

    try {
      const message = await chatApi.send(currentMissionId, content);
      set((state) => ({
        chatMessages: [...state.chatMessages, message],
      }));
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  approveAction: async (actionId, comment) => {
    const { currentMissionId } = get();
    if (!currentMissionId) return;

    try {
      await hitlApi.approve(currentMissionId, actionId, comment);
      set((state) => ({
        approvals: state.approvals.filter((a) => a.action_id !== actionId),
      }));
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  rejectAction: async (actionId, reason, comment) => {
    const { currentMissionId } = get();
    if (!currentMissionId) return;

    try {
      await hitlApi.reject(currentMissionId, actionId, reason, comment);
      set((state) => ({
        approvals: state.approvals.filter((a) => a.action_id !== actionId),
      }));
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  addEvent: (event) => {
    set((state) => ({
      events: [event, ...state.events].slice(0, 100),
    }));
  },

  toggleEventExpanded: (eventId) => {
    set((state) => ({
      events: state.events.map((e) =>
        e.id === eventId ? { ...e, expanded: !e.expanded } : e
      ),
    }));
  },

  updateTaskStatus: (taskId, status) => {
    set((state) => ({
      planTasks: state.planTasks.map((t) =>
        t.id === taskId ? { ...t, status } : t
      ),
    }));
  },

  clearError: () => set({ error: null }),

  reset: () => {
    const { wsConnection } = get();
    if (wsConnection) {
      wsConnection.disconnect();
    }
    set(initialState);
  },
}));

// Helper functions for event formatting
function getEventTitle(type: string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case "new_target":
      return `Target Discovered: ${d.ip}`;
    case "target_update":
      return `Target Updated: ${d.ip}`;
    case "new_vuln":
      return `Vulnerability Found: ${d.name}`;
    case "new_cred":
      return `Credential Harvested: ${d.username}`;
    case "new_session":
      return `Session Established: ${d.type}`;
    case "approval_request":
      return `Approval Required: ${d.action_type}`;
    case "mission_status":
      return `Mission Status: ${d.status}`;
    case "goal_achieved":
      return `Goal Achieved: ${d.goal}`;
    case "chat_message":
      return `Message from ${d.role}`;
    case "error":
      return `Error: ${d.message}`;
    default:
      return `Event: ${type}`;
  }
}

function getEventDescription(type: string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case "new_target":
      return `Discovered ${d.os || "Unknown OS"} at ${d.ip}`;
    case "new_vuln":
      return `${d.severity} severity - CVSS: ${d.cvss}`;
    case "new_cred":
      return `${d.type} credential for ${d.username}`;
    case "new_session":
      return `${d.type} session as ${d.user}`;
    case "approval_request":
      return d.action_description as string;
    default:
      return "";
  }
}

// Install zustand devtools in development
if (import.meta.env.DEV) {
  // @ts-expect-error - devtools extension
  window.__ZUSTAND_DEVTOOLS__ = useMissionStore;
}
