"use client";

import type { ScanProgress } from "@/lib/scanner/types";
import { cn } from "@/lib/utils";

export function ScanProgressBar({ progress }: { progress: ScanProgress }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-6">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium text-zinc-200">{progress.message}</span>
        <span className="text-sm text-zinc-500">{progress.progress}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-zinc-800">
        <div
          className={cn(
            "h-full rounded-full transition-all duration-500",
            progress.stage === "error" ? "bg-red-500" : "bg-emerald-500",
          )}
          style={{ width: `${progress.progress}%` }}
        />
      </div>
    </div>
  );
}
