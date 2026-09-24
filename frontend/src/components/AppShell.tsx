import type { Identity } from "../api/types";

export type AppView = "dashboard" | "simulations" | "new-simulation" | "detail" | "security";

interface AppShellProps {
  readonly children: React.ReactNode;
  readonly view: AppView;
  readonly apiStatus: "checking" | "online" | "offline";
  readonly lastRequestId: string | null;
  readonly onNavigate: (view: Exclude<AppView, "detail">) => void;
  readonly identity: Identity;
  readonly onLogout: () => void;
}

const baseNavigation: ReadonlyArray<{ readonly key: Exclude<AppView, "detail">; readonly label: string; readonly glyph: string }> = [
  { key: "dashboard", label: "Command center", glyph: "◈" },
  { key: "simulations", label: "Simulations", glyph: "◌" },
  { key: "new-simulation", label: "New simulation", glyph: "+" },
];

export function AppShell({ children, view, apiStatus, lastRequestId, onNavigate, identity, onLogout }: AppShellProps) {
  const navigation = identity.permissions.includes("security:admin") ? [...baseNavigation, { key: "security" as const, label: "Security", glyph: "⌾" }] : baseNavigation;
  return <div className="app-shell">
    <aside className="sidebar" aria-label="Primary navigation">
      <button className="brand" onClick={() => onNavigate("dashboard")} aria-label="Go to Command Center">
        <span className="brand-mark">A</span><span><b>AUTONOMOUS</b><small>RED TEAMING</small></span>
      </button>
      <nav>{navigation.map((item) => <button key={item.key} className={view === item.key || (view === "detail" && item.key === "simulations") ? "nav-item active" : "nav-item"} onClick={() => onNavigate(item.key)}><span>{item.glyph}</span>{item.label}</button>)}</nav>
      <div className="sidebar-foot"><span className={`health-dot ${apiStatus}`} /> API {apiStatus}</div>
    </aside>
    <main>
      <header className="topbar">
        <div><span className="eyebrow">DEFENSIVE SIMULATION PLATFORM</span><h1>COMMAND CENTER</h1></div>
        <div className="session-controls">
          <span className={`api-status ${apiStatus}`}><i /> API {apiStatus}</span>
          <div className="identity-chip"><span className="health-dot online" /><span><b>{identity.subject}</b><small>{identity.roles.join(", ")} · {identity.authentication.strength}</small></span></div>
          <button className="secondary-button" onClick={onLogout}>Sign out</button>
        </div>
      </header>
      <div className="request-strip">{identity.authentication.method.toUpperCase()} AUTHENTICATION · Credential retained in memory only{lastRequestId ? <span>LAST REQUEST <code>{lastRequestId}</code></span> : null}</div>
      <div className="content">{children}</div>
    </main>
  </div>;
}
