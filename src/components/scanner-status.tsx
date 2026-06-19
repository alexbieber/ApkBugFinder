import { cn } from "@/lib/utils";
import type { ScannerHealth } from "@/lib/scanner/api-client";
import { CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";

export function ScannerStatus({ health }: { health: ScannerHealth | null }) {
  if (health === null) {
    return (
      <div className="inline-flex items-center gap-2 rounded-full border border-zinc-800 bg-zinc-900/80 px-4 py-1.5 text-sm text-zinc-400">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Checking scanner…
      </div>
    );
  }

  const ready = health.status === "ok";

  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm",
        ready
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
          : "border-amber-500/30 bg-amber-500/10 text-amber-400",
      )}
    >
      {ready ? (
        <CheckCircle2 className="h-3.5 w-3.5" />
      ) : (
        <AlertTriangle className="h-3.5 w-3.5" />
      )}
      {ready
        ? "Full scanner online (JADX + dex2jar + 70+ MASVS rules)"
        : "Scanner offline — start with docker compose up or fall back to basic client scan"}
    </div>
  );
}
