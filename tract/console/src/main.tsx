import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity, Code2, Database, Eye, FileKey2, GitBranch, Globe,
  LockKeyhole, Network, Orbit, ScrollText, ShieldAlert, Sparkles, Terminal,
} from "lucide-react";
import "./styles.css";

type State = "normal" | "observe" | "restrict" | "quarantine" | "terminate";
type Agent = { id: string; name: string; parent?: string; state: State; x: number; y: number; cap: string[] };

const agents: Agent[] = [
  { id: "human", name: "HUMAN", state: "normal", x: 50, y: 12, cap: ["root.authority"] },
  { id: "0001", name: "orchestrator", parent: "human", state: "normal", x: 50, y: 33, cap: ["delegate", "repo.read"] },
  { id: "0011", name: "researcher", parent: "0001", state: "normal", x: 30, y: 56, cap: ["repo.read"] },
  { id: "0012", name: "coder", parent: "0001", state: "normal", x: 50, y: 56, cap: ["repo.read", "git.write"] },
  { id: "0013", name: "analyst", parent: "0001", state: "normal", x: 70, y: 56, cap: ["repo.read"] },
  { id: "0021", name: "browser", parent: "0011", state: "normal", x: 18, y: 81, cap: ["http.request"] },
  { id: "0022", name: "shell", parent: "0012", state: "quarantine", x: 38, y: 81, cap: ["shell.exec"] },
  { id: "0023", name: "git", parent: "0012", state: "restrict", x: 50, y: 81, cap: ["git.write"] },
  { id: "0024", name: "mcp", parent: "0013", state: "observe", x: 62, y: 81, cap: ["mcp.tool"] },
  { id: "xxxx", name: "external", parent: "0013", state: "terminate", x: 82, y: 81, cap: [] },
];

const liveEvents = [
  ["14:32:11", "ALLOW", "git.clone"],
  ["14:32:08", "WARN", "outbound.http"],
  ["14:31:59", "DENY", "shell.exec"],
  ["14:31:45", "ALLOW", "mcp.tool"],
  ["14:31:32", "QUAR", "unknown.agent"],
  ["14:31:10", "ALLOW", "repo.read"],
] as const;

const colors: Record<State, string> = {
  normal: "#21e779", observe: "#3f8eff", restrict: "#f2af18", quarantine: "#ff493c", terminate: "#cbd2d9",
};

function IconFor({ name }: { name: string }) {
  const Icon = name === "shell" ? Terminal : name === "git" ? GitBranch : name === "mcp" ? Database :
    name === "browser" ? Globe : name === "coder" ? Code2 : name === "external" ? ShieldAlert :
    name === "HUMAN" ? LockKeyhole : Activity;
  return <Icon aria-hidden="true" />;
}

function Lineage() {
  const byId = Object.fromEntries(agents.map((agent) => [agent.id, agent]));
  return <div className="lineage" aria-label="Synthetic agent lineage demonstration">
    <div className="sunDisc" aria-hidden="true"><Eye /></div>
    <div className="pyramid" aria-hidden="true" />
    <div className="lineageLegend">
      {([["normal","Authorized"],["observe","Monitoring"],["restrict","Restricted"],["quarantine","Blocked / Quarantined"],["terminate","Terminated"]] as const).map(([state,label]) =>
        <div key={state}><i style={{background: colors[state]}} />{label}</div>)}
      <div className="lineSample">Delegation</div><div className="lineSample alert">Alert / Anomaly</div>
    </div>
    <div className="riskOrb" aria-label="Synthetic risk field map"><span /><span /><span /><b>RISK FIELD</b></div>
    {agents.filter((agent) => agent.parent).map((agent) => {
      const parent = byId[agent.parent!];
      return <svg className="edge" key={`edge-${agent.id}`} aria-hidden="true">
        <line x1={`${parent.x}%`} y1={`${parent.y}%`} x2={`${agent.x}%`} y2={`${agent.y}%`}
          stroke={colors[agent.state]} strokeWidth="2" opacity=".74" />
      </svg>;
    })}
    {agents.map((agent) => <button key={agent.id} className={`agent ${agent.state}`}
      style={{ left: `${agent.x}%`, top: `${agent.y}%` }}
      aria-label={`${agent.name}, ${agent.state}, capabilities ${agent.cap.join(", ") || "none"}`}>
      <span><IconFor name={agent.name} /></span><b>{agent.name}</b>
      <small>{agent.id === "human" ? "Root Authority" : `agent:${agent.id}`}</small>
    </button>)}
  </div>;
}

function Mosaic() {
  const glyphs = ["◈", "⌁", "◇", "⊙", "✦", "◉"];
  return <div className="mosaic" aria-label="Synthetic signed event receipt mosaic">
    {Array.from({ length: 112 }, (_, i) => <span key={i} className={`tile t${i % 5}`}>{glyphs[i % glyphs.length]}</span>)}
  </div>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="panel"><h3>{title}</h3>{children}</section>;
}

function RevocationTree() {
  return <div className="revTree" aria-label="Synthetic revocation tree">
    <span className="r root" /><span className="r a" /><span className="r b" /><span className="r c" />
    <span className="r d" /><span className="r e" /><span className="r f" />
    <i className="rl one" /><i className="rl two" /><i className="rl three" /><i className="rl four" /><i className="rl five" /><i className="rl six" />
  </div>;
}

function CapabilityUsage() {
  const rows = [["repo.read",42],["git.write",18],["shell.exec",5],["http.request",22],["mcp.tool",9],["fs.write",4]] as const;
  return <div className="usage">{rows.map(([name,value]) => <div key={name}><span>{name}</span><i><b style={{width:`${value}%`}} /></i><em>{value}%</em></div>)}</div>;
}

function App() {
  const [view, setView] = useState("LIVE GRAPH");
  const counts = useMemo(() => ({
    Nodes: 28, Active: 24, Restricted: 3, Quarantined: 2, "Delegation Depth": 4, "Field Stability": "0.91", Anomalies: 2,
  }), []);

  const navigation = [
    ["LIVE GRAPH", Eye], ["AGENT PASSPORTS", FileKey2], ["EVENT LEDGER", ScrollText],
    ["THREAT VIEW", ShieldAlert], ["CAPABILITY MATRIX", Network], ["REVOCATION TREE", GitBranch],
    ["SYSTEM HEALTH", Activity], ["PHYSICS LATTICE", Orbit], ["MICRO MOSAIC VIEW", Sparkles],
  ] as const;

  return <main>
    <header className="ornateHeader">
      <div className="headerMark"><div className="wingMark">◆</div><div className="valueWords">HUMANITY<br/>ALIGNMENT<br/>ACCOUNTABILITY<br/>CONTINUITY</div></div>
      <div className="masthead">
        <div className="glyphBand">◇　◆　◇　◈　◇　◆　◇　◈　◇</div>
        <h1>TRACT v0.2 RUNTIME</h1>
        <p>TRACEABLE · AUTHENTIC · CONSTRAINED · TRANSPARENT</p>
        <strong>AI ACTION PROVENANCE & CAPABILITY CONTROL PLANE</strong>
        <small className="fixture">DEMO FIXTURE</small>
      </div>
      <div className="headerDoctrine">OBSERVE<br/>AUTHORIZE<br/>CONSTRAIN<br/>DETECT<br/>RESPOND<br/>PROVE</div>
      <div className="headerQuote"><div className="ankh" aria-hidden="true">☥</div><q>ALL ACTIONS LEAVE A TRACE<br/>ALL TRACES TELL A STORY<br/>ALL STORIES MUST BE TRUE</q></div>
    </header>

    <div className="shell">
      <nav aria-label="TRACT console views">
        {navigation.map(([name, Icon]) => <button className={view === name ? "active" : ""} onClick={() => setView(name)} key={name}>
          <Icon aria-hidden="true" /> <span>{name}</span>
        </button>)}
      </nav>

      <section className="center">
        <div className="titleRow">
          <div><h2>LIVE AGENT LINEAGE</h2><p>REAL-TIME FROM EVENT RECEIPTS</p></div>
          <div><h2>RISK FIELD MAP</h2><p>BEHAVIORAL + PHYSICAL GEOMETRY</p></div>
        </div>
        <Lineage />
        <div className="mosaicHead">
          <div><h3>EVENT MOSAIC TIMELINE</h3><small>EACH TILE = SIGNED EVENT RECEIPT</small></div>
          <small>TAMPER EVIDENT · HASH LINKED · VERIFIABLE</small>
        </div>
        <Mosaic />
      </section>

      <aside>
        <Panel title="SYSTEM STATUS"><ul className="status">
          {["Gateway", "Passport Verifier", "Ethos Aegis", "Ledger", "Revocation Store", "Interceptors", "Visualization"].map((item) =>
            <li key={item}><span>{item}</span><b>Online</b></li>)}
        </ul></Panel>
        <Panel title="LIVE EVENTS"><div className="events">
          {liveEvents.map((event) => <div key={event.join()}><time>{event[0]}</time><b className={event[1]}>{event[1]}</b><span>{event[2]}</span></div>)}
        </div></Panel>
        <Panel title="THREAT CLASSIFICATION"><ul className="threat">
          <li><i className="dot normal" />Normal <b>1,240</b></li>
          <li><i className="dot observe" />Observe <b>128</b></li>
          <li><i className="dot restrict" />Restrict <b>37</b></li>
          <li><i className="dot quarantine" />Quarantine <b>12</b></li>
          <li><i className="dot terminate" />Terminate <b>3</b></li>
        </ul></Panel>
        <Panel title="CAPABILITY USAGE"><CapabilityUsage /></Panel>
      </aside>
    </div>

    <section className="bottom">
      <Panel title="GEOMETRIC INSIGHTS"><div className="insight"><div className="compass"><i/><i/><b/></div>
        {Object.entries(counts).map(([key, value]) => <div key={key}><span>{key}</span><b>{value}</b></div>)}
      </div></Panel>
      <Panel title="PHYSICS-BASED ANOMALY DETECTION"><div className="fields">
        {["Behavioral Field", "Entropy Deviation", "Flow Irregularity", "Capability Resonance"].map((name, index) =>
          <div key={name}><span>{name}</span><i className={`field f${index}`} /></div>)}
      </div></Panel>
      <Panel title="REVOCATION TREE"><RevocationTree /></Panel>
      <Panel title="AGENT PASSPORT (SELECTED)"><dl>
        <dt>agent_id</dt><dd>agent:0012</dd><dt>parent_id</dt><dd>agent:0001</dd>
        <dt>model</dt><dd>openai:gpt-4o</dd><dt>purpose</dt><dd>develop features</dd>
        <dt>capabilities</dt><dd>[repo.read, git.write]</dd><dt>restrictions</dt><dd>[shell.*, network.raw]</dd>
        <dt>expires</dt><dd>2026-09-19T05:00:00Z</dd><dt>status</dt><dd className="valid">VALID</dd>
      </dl></Panel>
    </section>

    <footer><b>TRACT v0.2</b><span>PAST IS PROOF · PRESENT IS PROTECTION · FUTURE IS ALIGNMENT　∞</span><small>BUILT ON AGI-CP · ETHOS AEGIS · MISE BRIGADE · SOVEREIGN LATTICE</small></footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(<App />);
