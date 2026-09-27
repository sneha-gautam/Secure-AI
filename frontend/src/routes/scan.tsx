import { createFileRoute, Link } from "@tanstack/react-router";
import { Check, Circle, LoaderCircle, ScanLine } from "lucide-react";
import { useEffect, useState } from "react";
import { PageHeader, Panel } from "@/components/app-shell";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/scan")({
  head: () => ({ meta: [
    { title: "Scan Application — SecureAI" }, { name: "description", content: "Run a simple mock vulnerability scan with SecureAI." },
    { property: "og:title", content: "Scan Application — SecureAI" }, { property: "og:description", content: "Run a simple mock vulnerability scan with SecureAI." },
    { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" },
  ] }), component: ScanPage,
});

const checks = ["SQL Injection", "Cross-Site Scripting (XSS)", "Security Headers"];

function ScanPage() {
  const [progress, setProgress] = useState(0);
  const scanning = progress > 0 && progress < 100;
  useEffect(() => { if (!scanning) return; const timer = window.setInterval(() => setProgress((value) => Math.min(100, value + 4)), 120); return () => window.clearInterval(timer); }, [scanning]);
  return <>
    <PageHeader eyebrow="New scan" title="Scan application" description="Check the target for the most common web security issues." />
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(320px,.7fr)]">
      <Panel><label htmlFor="target" className="text-sm font-semibold">Target application</label><div className="mt-3 flex flex-col gap-3 sm:flex-row"><input id="target" defaultValue="https://demo.secureai.app" className="h-11 min-w-0 flex-1 rounded-md border border-input bg-background px-3 font-mono text-sm text-foreground outline-none transition focus:border-primary focus:ring-2 focus:ring-ring" /><Button size="lg" onClick={() => setProgress(1)} disabled={scanning}><ScanLine className="size-4" />{scanning ? "Scanning..." : progress === 100 ? "Scan Again" : "Start Scan"}</Button></div><p className="mt-3 text-xs text-muted-foreground">This prototype uses mock results and does not send any requests.</p>
        <div className="mt-8 border-t border-border pt-6"><div className="flex justify-between text-sm"><span className="font-medium">Scan progress</span><span className="font-mono text-primary">{progress}%</span></div><div className="mt-3 h-2 overflow-hidden rounded-full bg-muted"><div className="h-full bg-primary transition-[width] duration-150" style={{ width: `${progress}%` }} /></div><p className="mt-3 text-xs text-muted-foreground">{progress === 0 ? "Ready to scan" : progress < 100 ? "Reviewing application routes and responses..." : "Scan complete — 3 findings detected."}</p></div>
      </Panel>
      <Panel><h2 className="font-display text-lg font-semibold">Security checks</h2><div className="mt-5 space-y-3">{checks.map((check, index) => { const done = progress >= (index + 1) * 30; const active = progress > index * 30 && !done; return <div key={check} className="flex items-center gap-3 rounded-md border border-border bg-background p-3"><span className={`grid size-8 place-items-center rounded-md ${done ? "bg-success-soft text-success" : active ? "bg-warning-soft text-warning" : "bg-muted text-muted-foreground"}`}>{done ? <Check className="size-4" /> : active ? <LoaderCircle className="size-4 animate-spin" /> : <Circle className="size-3" />}</span><div><p className="text-sm font-medium">{check}</p><p className="text-xs text-muted-foreground">{done ? "Check complete" : active ? "Checking..." : "Waiting"}</p></div></div>; })}</div>{progress === 100 && <Button asChild className="mt-5 w-full"><Link to="/findings">Review findings</Link></Button>}</Panel>
    </div>
  </>;
}
