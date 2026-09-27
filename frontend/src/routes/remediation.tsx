import { createFileRoute, Link } from "@tanstack/react-router";
import { Bot, Check, Code2, Lightbulb, X } from "lucide-react";
import { PageHeader, Panel, StatusPill } from "@/components/app-shell";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/remediation")({
  validateSearch: (search: Record<string, unknown>) => ({ finding: typeof search["finding"] === "string" ? search["finding"] : "SQL Injection" }),
  head: () => ({ meta: [
    { title: "AI Remediation — SecureAI" }, { name: "description", content: "Review a clear AI explanation and safe fix recommendation." },
    { property: "og:title", content: "AI Remediation — SecureAI" }, { property: "og:description", content: "Review a clear AI explanation and safe fix recommendation." },
    { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" },
  ] }), component: RemediationPage,
});

function RemediationPage() {
  const { finding } = Route.useSearch();
  return <><PageHeader eyebrow="AI-assisted remediation" title="Review recommended fix" description="SecureAI explains the issue and proposes a safe code change for approval." />
    <Panel><div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-xs uppercase tracking-[0.12em] text-muted-foreground">Selected vulnerability</p><h2 className="mt-2 font-display text-2xl font-semibold">{finding}</h2><p className="mt-1 font-mono text-xs text-muted-foreground">GET /search?q=...</p></div><StatusPill tone="danger">High severity</StatusPill></div></Panel>
    <div className="mt-5 grid gap-5 lg:grid-cols-2"><Panel><div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-md bg-accent text-primary"><Bot className="size-4" /></span><h2 className="font-display text-lg font-semibold">AI explanation</h2></div><p className="mt-5 text-sm leading-7 text-muted-foreground">The search query is inserted directly into a database command. An attacker could change that command and access information they should not see.</p></Panel><Panel><div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-md bg-success-soft text-success"><Lightbulb className="size-4" /></span><h2 className="font-display text-lg font-semibold">Recommended fix</h2></div><p className="mt-5 text-sm leading-7 text-muted-foreground">Use a parameterized query so the database treats the search term as data, never as executable code.</p></Panel></div>
    <Panel className="mt-5 p-0"><div className="flex items-center gap-2 border-b border-border px-5 py-4"><Code2 className="size-4 text-primary" /><h2 className="font-display font-semibold">Proposed code change</h2></div><div className="grid font-mono text-xs leading-6 lg:grid-cols-2"><div className="border-b border-border p-5 lg:border-b-0 lg:border-r"><p className="mb-3 font-sans text-[10px] font-bold uppercase tracking-[0.14em] text-danger">Before</p><pre className="overflow-x-auto text-muted-foreground"><code><span className="text-danger">-</span>{" const query = `SELECT * FROM products"}<br/>{"  WHERE name LIKE '%${search}%'`;"}<br/><span className="text-danger">-</span>{" db.execute(query);"}</code></pre></div><div className="p-5"><p className="mb-3 font-sans text-[10px] font-bold uppercase tracking-[0.14em] text-success">After</p><pre className="overflow-x-auto text-muted-foreground"><code><span className="text-success">+</span>{" const query = `SELECT * FROM products"}<br/>{"  WHERE name LIKE ?`;"}<br/><span className="text-success">+</span>{" db.execute(query, [`%${search}%`]);"}</code></pre></div></div></Panel>
    <div className="mt-5 flex flex-col-reverse justify-end gap-3 sm:flex-row"><Button variant="outline" asChild><Link to="/findings"><X className="size-4" />Reject</Link></Button><Button asChild><Link to="/verification"><Check className="size-4" />Approve Fix</Link></Button></div>
  </>;
}
