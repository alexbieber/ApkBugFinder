import type { Confidence } from "@/lib/scanner/types";
import { cn } from "@/lib/utils";

const STYLES: Record<Confidence, string> = {
  confirmed: "border-red-500/40 bg-red-500/10 text-red-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  medium: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  low: "border-zinc-600 bg-zinc-800 text-zinc-400",
  informational: "border-zinc-700 bg-zinc-800/80 text-zinc-500",
};

const LABELS: Record<Confidence, string> = {
  confirmed: "Confirmed",
  high: "High confidence",
  medium: "Review",
  low: "Low signal",
  informational: "Info",
};

export function ConfidenceBadge({ confidence }: { confidence?: Confidence }) {
  if (!confidence) return null;
  return (
    <span
      className={cn(
        "rounded border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        STYLES[confidence],
      )}
    >
      {LABELS[confidence]}
    </span>
  );
}

export function isActionable(confidence?: Confidence, severity?: string, id?: string): boolean {
  if (confidence === "confirmed" || confidence === "high") return true;
  if (confidence === "medium") {
    if (severity === "critical" || severity === "high") return true;
    if (id?.startsWith("ADV-SECRET") || id === "MSTG-NETWORK-1-NOCONFIG") return true;
  }
  return false;
}
