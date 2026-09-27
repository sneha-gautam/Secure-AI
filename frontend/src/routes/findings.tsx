import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, Filter, Search } from "lucide-react";
import { PageHeader, Panel, StatusPill } from "@/components/app-shell";

export const Route = createFileRoute("/findings")({
  head: () => ({ meta: [
    { title: "Findings — SecureAI" }, { name: "description", content: "Review vulnerabilities detected by SecureAI." },
    { property: "og:title", content: "Findings — SecureAI" }, { property: "og:description", content: "Review vulnerabilities detected by SecureAI." },
    { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" },
  ] }), component: FindingsPage,
});

const findings = [
  { name: "SQL Injection", severity: "High", path: "/search", status: "Open", tone: "danger" as const },
  { name: "XSS", severity: "Medium", path: "/comments", status: "Open", tone: "warning" as const },
  { name: "Missing Security Headers", severity: "Medium", path: "/", status: "Open", tone: "warning" as const },
];

function FindingsPage() {
  return <><PageHeader eyebrow="Scan results" title="Findings" description="Three vulnerabilities were detected in the latest scan." />
    <Panel className="p-0"><div className="flex flex-col gap-3 border-b border-border p-4 sm:flex-row sm:items-center sm:justify-between"><div className="relative"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><input aria-label="Search findings" placeholder="Search findings" className="h-9 w-full rounded-md border border-input bg-background pl-9 pr-3 text-sm outline-none focus:border-primary sm:w-64" /></div><div className="flex items-center gap-2 text-xs text-muted-foreground"><Filter className="size-3.5" />3 open findings</div></div>
      <div className="overflow-x-auto"><table className="w-full min-w-[680px] text-left"><thead><tr className="border-b border-border text-[10px] uppercase tracking-[0.14em] text-muted-foreground"><th className="px-5 py-3 font-semibold">Vulnerability</th><th className="px-5 py-3 font-semibold">Severity</th><th className="px-5 py-3 font-semibold">Affected path</th><th className="px-5 py-3 font-semibold">Status</th><th className="w-12" /></tr></thead><tbody>{findings.map((finding) => <tr key={finding.name} className="border-b border-border last:border-0 hover:bg-accent"><td className="px-5 py-5 font-medium"><Link to="/remediation" search={{ finding: finding.name }} className="hover:text-primary">{finding.name}</Link></td><td className="px-5 py-5"><StatusPill tone={finding.tone}>{finding.severity}</StatusPill></td><td className="px-5 py-5 font-mono text-xs text-muted-foreground">{finding.path}</td><td className="px-5 py-5 text-xs text-muted-foreground">{finding.status}</td><td className="px-5 py-5"><Link to="/remediation" search={{ finding: finding.name }} aria-label={`Open ${finding.name}`} className="text-muted-foreground hover:text-primary"><ArrowRight className="size-4" /></Link></td></tr>)}</tbody></table></div>
    </Panel></>;
}
