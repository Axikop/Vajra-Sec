import { NavLink, Outlet } from "react-router-dom";
import { Activity, Shield, Search, Github, Server, Wand2 } from "lucide-react";
import { cn } from "@/lib/utils";

const navItems = [
  { to: "/",         label: "Dashboard",  icon: Activity },
  { to: "/lookup",   label: "CVE Lookup", icon: Search   },
  { to: "/fofa-gpt", label: "FofaGPT",    icon: Wand2    },
];

export default function Layout() {
  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-60 shrink-0 border-r border-border bg-surface/50 flex flex-col">
        <div className="px-5 py-5 flex items-center gap-2 border-b border-border">
          <div className="h-8 w-8 rounded-md bg-gradient-to-br from-accent/40 to-critical/40 grid place-items-center">
            <Shield className="h-4 w-4 text-white" strokeWidth={2.5} />
          </div>
          <div>
            <div className="text-sm font-semibold tracking-tight">Attack Surface</div>
            <div className="text-[10px] uppercase tracking-widest text-muted">Monitor</div>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                  isActive
                    ? "bg-elev text-text border border-border"
                    : "text-muted hover:text-text hover:bg-elev/60",
                )
              }
            >
              <Icon className="h-4 w-4" strokeWidth={2} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="p-3 mt-auto border-t border-border space-y-1 text-[11px] text-muted">
          <div className="flex items-center gap-2 px-2 py-1">
            <Server className="h-3 w-3" />
            <span>API · localhost:5000</span>
          </div>
          <div className="flex items-center gap-2 px-2 py-1">
            <Github className="h-3 w-3" />
            <span>v1.0.0</span>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 border-b border-border bg-surface/40 backdrop-blur-sm flex items-center justify-between px-6">
          <div className="text-xs text-muted">
            CVE Intelligence Platform · Indian Critical Sector Monitoring
          </div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
            <span className="text-[11px] text-muted">Service online</span>
          </div>
        </header>

        <div className="flex-1 p-6 overflow-y-auto scrollbar-thin">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
