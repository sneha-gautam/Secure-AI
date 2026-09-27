import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, Check, ShieldCheck } from "lucide-react";
import { PageHeader, Panel, StatusPill } from "@/components/app-shell";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/verification")({
  head: () => ({ meta: [
    { title: "Verification — SecureAI" }, { name: "description", content: "View SecureAI security and functionality verification results." },
    { property: "og:title", content: "Verification — SecureAI" }, { property: "og:description", content: "View SecureAI security and functionality verification results." },
    { property: "og:type", content: "website" }, { name: "twitter:card", content: "summary_large_image" },
  ] }), component: VerificationPage,
});

function VerificationPage() {
  return <><PageHeader eyebrow="Verification complete" title="Fix verified" description="The approved change passed both security and functionality checks." />
    <div className="mx-auto max-w-3xl"><Panel className="overflow-hidden p-0"><div className="border-b border-border bg-success-soft px-6 py-9 text-center"><div className="mx-auto grid size-16 place-items-center rounded-full border border-success/30 bg-background text-success shadow-success"><ShieldCheck className="size-8" /></div><p className="mt-5 text-xs font-semibold uppercase tracking-[0.18em] text-success">Final verdict</p><h2 className="mt-2 font-display text-4xl font-bold">VERIFIED</h2></div><div className="divide-y divide-border px-6">{["Security Verification", "Functionality Verification"].map((item) => <div key={item} className="flex items-center justify-between gap-4 py-5"><div className="flex items-center gap-3"><span className="grid size-8 place-items-center rounded-full bg-success-soft text-success"><Check className="size-4" /></span><span className="font-medium">{item}</span></div><StatusPill tone="success">Passed</StatusPill></div>)}</div><div className="border-t border-border bg-background px-6 py-4 text-center text-xs text-muted-foreground">Verified today at 09:46 · Mock verification run</div></Panel><div className="mt-5 flex justify-center"><Button asChild><Link to="/">Return to dashboard <ArrowRight className="size-4" /></Link></Button></div></div>
  </>;
}
