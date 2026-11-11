import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth";
import { useTheme } from "../theme";

export function AppShell() {
  const { user, signOut } = useAuth();
  const [theme, toggleTheme] = useTheme();

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-ink)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z" />
              <path d="m9 12 2.2 2.2L15.5 10" />
            </svg>
          </span>
          SecurlyQ
        </div>
        <nav className="nav" aria-label="Main">
          <NavLink to="/alerts">Alerts</NavLink>
          <span className="nav-off" aria-disabled="true">
            Events <span className="soon">soon</span>
          </span>
          <span className="nav-off" aria-disabled="true">
            Model health <span className="soon">soon</span>
          </span>
        </nav>
        <div style={{ marginTop: "auto", display: "flex", flexDirection: "column", gap: 12 }}>
          <button className="btn btn-sm" type="button" onClick={toggleTheme} aria-pressed={theme === "light"}>
            {theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          </button>
          <div style={{ padding: "0 8px" }}>
            <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis" }}>{user?.email}</div>
            <div className="muted" style={{ fontSize: 12 }}>
              {user?.role}
            </div>
          </div>
          <button className="btn btn-sm" type="button" onClick={signOut}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
