// RAGLOX v3.0 - Sidebar Component (Manus Icon-Only Style)
// Minimal sidebar with icons only - matches Manus warm dark theme

import { useState } from "react";
import { motion } from "framer-motion";
import { 
  Shield,
  PenSquare,
  Search,
  Library,
  FileText,
  Settings,
  HelpCircle,
  Bell,
  Link2
} from "lucide-react";
import { cn } from "@/lib/utils";

interface SidebarProps {
  activeItem?: string;
  onItemClick?: (item: string) => void;
  className?: string;
}

export function Sidebar({
  activeItem = "home",
  onItemClick,
  className,
}: SidebarProps) {
  const [hoveredItem, setHoveredItem] = useState<string | null>(null);

  const topItems = [
    { id: "home", icon: Shield, label: "RAGLOX" },
    { id: "new", icon: PenSquare, label: "New Task" },
    { id: "search", icon: Search, label: "Search" },
    { id: "library", icon: Library, label: "Library" },
    { id: "files", icon: FileText, label: "Files" },
  ];

  const bottomItems = [
    { id: "settings", icon: Settings, label: "Settings" },
    { id: "help", icon: HelpCircle, label: "Help" },
    { id: "notifications", icon: Bell, label: "Notifications" },
    { id: "connect", icon: Link2, label: "Connect" },
  ];

  return (
    <div 
      className={cn(
        "flex flex-col h-full w-[60px] py-4",
        className
      )}
      style={{ 
        background: '#141414',
        borderRight: '1px solid rgba(255, 255, 255, 0.06)',
        boxShadow: '4px 0 16px rgba(0, 0, 0, 0.1)'
      }}
    >
      {/* Top Navigation */}
      <div className="flex flex-col items-center gap-1">
        {topItems.map((item) => (
          <SidebarIcon
            key={item.id}
            icon={item.icon}
            label={item.label}
            isActive={activeItem === item.id}
            isHovered={hoveredItem === item.id}
            onMouseEnter={() => setHoveredItem(item.id)}
            onMouseLeave={() => setHoveredItem(null)}
            onClick={() => onItemClick?.(item.id)}
            isLogo={item.id === "home"}
          />
        ))}
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Bottom Navigation */}
      <div className="flex flex-col items-center gap-1">
        {bottomItems.map((item) => (
          <SidebarIcon
            key={item.id}
            icon={item.icon}
            label={item.label}
            isActive={activeItem === item.id}
            isHovered={hoveredItem === item.id}
            onMouseEnter={() => setHoveredItem(item.id)}
            onMouseLeave={() => setHoveredItem(null)}
            onClick={() => onItemClick?.(item.id)}
          />
        ))}
      </div>
    </div>
  );
}

// Sidebar Icon Component
interface SidebarIconProps {
  icon: React.ElementType;
  label: string;
  isActive?: boolean;
  isHovered?: boolean;
  isLogo?: boolean;
  onMouseEnter?: () => void;
  onMouseLeave?: () => void;
  onClick?: () => void;
}

function SidebarIcon({
  icon: Icon,
  label,
  isActive,
  isHovered,
  isLogo,
  onMouseEnter,
  onMouseLeave,
  onClick,
}: SidebarIconProps) {
  return (
    <div className="relative">
      <button
        className={cn(
          "p-3 rounded-xl transition-all duration-200",
          isActive && "bg-[#1f1f1f]",
          !isActive && "hover:bg-[#1f1f1f]"
        )}
        style={{
          color: isActive ? '#4a9eff' : isLogo ? '#4a9eff' : '#888888',
        }}
        onMouseEnter={onMouseEnter}
        onMouseLeave={onMouseLeave}
        onClick={onClick}
      >
        <Icon 
          className={cn("sidebar-icon", isLogo && "w-6 h-6")} 
          strokeWidth={1.5}
        />
      </button>
      
      {/* Tooltip */}
      {isHovered && (
        <motion.div
          initial={{ opacity: 0, x: -5 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -5 }}
          className="absolute left-full top-1/2 -translate-y-1/2 ml-2 px-2 py-1 rounded-md text-xs whitespace-nowrap z-50"
          style={{
            background: '#2a2a2a',
            color: '#e8e8e8',
            boxShadow: '0 4px 16px rgba(0,0,0,0.12)',
          }}
        >
          {label}
        </motion.div>
      )}
    </div>
  );
}

export default Sidebar;
