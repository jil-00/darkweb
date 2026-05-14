import { Activity, Search, Bell, Users, LogOut, Radar } from "lucide-react";

interface SidebarProps {
  view: "dashboard" | "search" | "alerts" | "admin";
  onViewChange: (view: "dashboard" | "search" | "alerts" | "admin") => void;
  onLogout: () => void;
}

export function Sidebar({ view, onViewChange, onLogout }: SidebarProps) {
  const navItems = [
    { key: "dashboard", label: "Dashboard", icon: Activity },
    { key: "search", label: "Search", icon: Search },
    { key: "alerts", label: "Alerts", icon: Bell },
    { key: "admin", label: "Admin", icon: Users }
  ] as const;

  return (
    <aside className="sidebar">
      {/* Sidebar Header */}
      <div className="sidebar-header">
        <Radar size={28} className="text-blue-600" />
        <h1>RJ Intelligence</h1>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {navItems.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            className={`nav-item ${view === key ? "active" : ""}`}
            onClick={() => onViewChange(key)}
            title={label}
          >
            <Icon size={20} />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <button
          className="logout-btn"
          onClick={onLogout}
          title="Sign out of your account"
        >
          <LogOut size={18} className="mr-2" />
          Logout
        </button>
      </div>
    </aside>
  );
}
