import { cn } from "@/lib/utils";
import { ReactNode } from "react";

type Variant = "default" | "critical" | "high" | "medium" | "low" | "info" | "muted";

const variants: Record<Variant, string> = {
  default:  "bg-elev text-text border-border",
  critical: "bg-critical/15 text-critical border-critical/40",
  high:     "bg-danger/15 text-danger border-danger/40",
  medium:   "bg-warn/15 text-warn border-warn/40",
  low:      "bg-success/15 text-success border-success/40",
  info:     "bg-accent/15 text-accent border-accent/40",
  muted:    "bg-elev text-muted border-border",
};

export function Badge({
  variant = "default",
  children,
  className,
}: {
  variant?: Variant;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        variants[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function severityVariant(sev: string | null | undefined): Variant {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH":     return "high";
    case "MEDIUM":   return "medium";
    case "LOW":      return "low";
    default:         return "muted";
  }
}
