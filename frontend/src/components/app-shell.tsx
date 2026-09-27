import { Link, useRouterState } from "@tanstack/react-router";
import { Activity, LayoutDashboard, ListChecks, ScanLine, ShieldCheck, Sparkles } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const navigation = [
  { to: "/" as const, label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan" as const, label: "Scan", icon: ScanLine },
  { to: "/findings" as const, label: "Findings", icon: ListChecks },
  { to: "/remediation" as const, label: "Remediation", icon: Sparkles },
  { to: "/verification" as const, label: "Verification", icon: ShieldCheck },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 border-r border-border bg-sidebar lg:flex lg:flex-col">
        <div className="flex h-20 items-center gap-3 border-b border-border px-6">
          <div className="grid size-9 place-items-center rounded-md bg-primary text-primary-foreground shadow-accent">
            <ShieldCheck className="size-5" />
          </div>
          <div>
            <div className="font-display text-lg font-bold">Secure<span className="text-primary">AI</span></div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Web security</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-6" aria-label="Main navigation">
          {navigation.map((item) => {
            const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
            const Icon = item.icon;
            return (
              <Link key={item.to} to={item.to} className={cn("group flex h-11 items-center gap-3 rounded-md border-l-2 px-3 text-sm transition-colors", active ? "border-primary bg-accent text-foreground" : "border-transparent text-muted-foreground hover:bg-accent hover:text-foreground")}>
                <Icon className={cn("size-4", active && "text-primary")} />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border p-5">
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="relative flex size-2"><span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-50" /><span className="relative inline-flex size-2 rounded-full bg-success" /></span>
            Prototype environment
          </div>
        </div>
      </aside>

      <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur lg:hidden">
        <Link to="/" className="font-display text-lg font-bold">Secure<span className="text-primary">AI</span></Link>
        <div className="flex items-center gap-1 overflow-x-auto" aria-label="Mobile navigation">
          {navigation.map((item) => {
            const active = item.to === "/" ? pathname === "/" : pathname.startsWith(item.to);
            const Icon = item.icon;
            return <Link key={item.to} to={item.to} aria-label={item.label} title={item.label} className={cn("grid size-9 shrink-0 place-items-center rounded-md text-muted-foreground", active && "bg-accent text-primary")}><Icon className="size-4" /></Link>;
          })}
        </div>
      </header>

      <main className="lg:pl-60">
        <div className="mx-auto min-h-screen max-w-[1440px] px-4 py-6 sm:px-7 lg:px-10 lg:py-9">{children}</div>
      </main>
    </div>
  );
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return (
    <header className="mb-8 flex flex-col gap-5 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-primary"><Activity className="size-3.5" />{eyebrow}</div>
        <h1 className="font-display text-3xl font-semibold sm:text-4xl">{title}</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">{description}</p>
      </div>
      {action}
    </header>
  );
}

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn("rounded-lg border border-border bg-card p-5 shadow-panel", className)}>{children}</section>;
}

export function StatusPill({ children, tone = "warning" }: { children: ReactNode; tone?: "danger" | "warning" | "success" }) {
  return <span className={cn("inline-flex items-center rounded-sm px-2 py-1 text-[10px] font-bold uppercase", tone === "danger" && "bg-danger-soft text-danger", tone === "warning" && "bg-warning-soft text-warning", tone === "success" && "bg-success-soft text-success")}>{children}</span>;
}
