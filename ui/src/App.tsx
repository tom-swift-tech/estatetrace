import { NavLink, Route, Routes } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, ensureSession } from "./api";
import Inbox from "./pages/Inbox";
import Scope from "./pages/Scope";
import Resources from "./pages/Resources";
import ResourceDetail from "./pages/ResourceDetail";
import Compliance from "./pages/Compliance";
import Packs from "./pages/Packs";
import Exports from "./pages/Exports";
import Operations from "./pages/Operations";
import Settings from "./pages/Settings";

export default function App() {
  const [themeCss, setThemeCss] = useState("");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      await ensureSession();
      try {
        const t = await api<{ css: string }>("/theme");
        setThemeCss(t.css || "");
      } catch {
        /* disconnected theme ok */
      }
      setReady(true);
    })();
  }, []);

  if (!ready) return <div className="main">Loading EstateTrace…</div>;

  return (
    <div className="shell">
      <style>{themeCss}</style>
      <aside className="sidebar">
        <div className="brand">EstateTrace</div>
        <nav className="nav">
          <NavLink to="/" end>
            Change inbox
          </NavLink>
          <NavLink to="/operations">ServiceNow ops</NavLink>
          <NavLink to="/compliance">Compliance</NavLink>
          <NavLink to="/scope">Azure scope</NavLink>
          <NavLink to="/resources">Resources</NavLink>
          <NavLink to="/packs">Policy packs</NavLink>
          <NavLink to="/exports">Exports</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
      </aside>
      <div className="content">
        <header className="header">
          <div>Production change inbox</div>
          <div className="muted" style={{ color: "#d9e2ec" }}>
            Local Azure MVP
          </div>
        </header>
        <main className="main">
          <Routes>
            <Route path="/" element={<Inbox />} />
            <Route path="/operations" element={<Operations />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/scope" element={<Scope />} />
            <Route path="/resources" element={<Resources />} />
            <Route path="/resources/*" element={<ResourceDetail />} />
            <Route path="/packs" element={<Packs />} />
            <Route path="/exports" element={<Exports />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}