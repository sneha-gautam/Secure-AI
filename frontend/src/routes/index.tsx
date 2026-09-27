import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, CalendarClock, ScanLine, ShieldCheck, TriangleAlert } from "lucide-react";
import { PageHeader, Panel, StatusPill } from "@/components/app-shell";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({ meta: [
    { title: "Dashboard — SecureAI" },
    { name: "description", content: "SecureAI security overview and recent vulnerability findings." },
    { property: "og:title", content: "Dashboard — SecureAI" },
    { property: "og:description", content: "SecureAI security overview and recent vulnerability findings." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: Dashboard,
});

const findings = [
  { name: "SQL Injection", level: "High", path: "/search", tone: "danger" as const },
  { name: "Cross-Site Scripting", level: "Medium", path: "/comments", tone: "warning" as const },
  { name: "Missing Security Headers", level: "Medium", path: "/", tone: "warning" as const },
];

function Dashboard() {
  return <>
    <PageHeader eyebrow="Security overview" title="Good morning, Sneha" description="Here is the current security posture for your target application." action={<Button asChild size="lg"><Link to="/scan"><ScanLine className="size-4" />Start Scan</Link></Button>} />
    <div className="grid gap-4 md:grid-cols-3">
      <Panel className="relative overflow-hidden"><div className="absolute right-0 top-0 h-full w-1 bg-primary" /><p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Security Score</p><div className="mt-5 flex items-end gap-3"><span className="font-display text-5xl font-semibold">72</span><span className="mb-1 text-sm text-muted-foreground">/ 100</span></div><div className="mt-5 h-1.5 overflow-hidden rounded-full bg-muted"><div className="h-full w-[72%] bg-primary" /></div></Panel>
      <Panel><div className="flex items-start justify-between"><div><p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Open Findings</p><p className="mt-5 font-display text-5xl font-semibold">3</p></div><div className="grid size-10 place-items-center rounded-md bg-danger-soft text-danger"><TriangleAlert className="size-5" /></div></div><p className="mt-5 text-sm text-muted-foreground"><span className="font-medium text-danger">1 high risk</span> needs attention</p></Panel>
      <Panel><div className="flex items-start justify-between"><div><p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Last Scan</p><p className="mt-5 font-display text-2xl font-semibold">Today, 09:42</p></div><div className="grid size-10 place-items-center rounded-md bg-success-soft text-success"><CalendarClock className="size-5" /></div></div><p className="mt-7 text-sm text-muted-foreground">Completed in 38 seconds</p></Panel>
    </div>
    <Panel className="mt-5 p-0"><div className="flex items-center justify-between border-b border-border px-5 py-4"><div><h2 className="font-display text-lg font-semibold">Recent Findings</h2><p className="mt-1 text-xs text-muted-foreground">From the latest scan of demo.secureai.app</p></div><Button variant="ghost" size="sm" asChild><Link to="/findings">View all <ArrowRight className="size-3.5" /></Link></Button></div><div className="divide-y divide-border">{findings.map((finding) => <Link key={finding.name} to="/remediation" search={{ finding: finding.name }} className="grid grid-cols-[1fr_auto] items-center gap-4 px-5 py-4 transition-colors hover:bg-accent sm:grid-cols-[1fr_140px_100px_24px]"><div className="flex items-center gap-3"><span className="grid size-8 place-items-center rounded-md bg-accent text-primary"><ShieldCheck className="size-4" /></span><span className="font-medium">{finding.name}</span></div><span className="hidden font-mono text-xs text-muted-foreground sm:block">{finding.path}</span><StatusPill tone={finding.tone}>{finding.level}</StatusPill><ArrowRight className="hidden size-4 text-muted-foreground sm:block" /></Link>)}</div></Panel>
  </>;
}
