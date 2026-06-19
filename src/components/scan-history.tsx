"use client";

import Link from "next/link";
import type { ScanResult } from "@/lib/scanner/types";
import { formatDate, formatDuration } from "@/lib/utils";
import { Clock, ChevronRight } from "lucide-react";

export function ScanHistory({ scans }: { scans: ScanResult[] }) {
  if (scans.length === 0) return null;

  return (
    <div className="mt-12">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-zinc-500">
        Recent Scans
      </h2>
      <div className="space-y-2">
        {scans.slice(0, 5).map((scan) => (
          <Link
            key={scan.id}
            href={`/scan/${scan.id}`}
            className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 transition hover:border-zinc-700 hover:bg-zinc-900"
          >
            <div className="min-w-0">
              <p className="truncate font-medium text-zinc-200">
                {scan.appInfo.fileName}
              </p>
              <p className="flex items-center gap-2 text-xs text-zinc-500">
                <Clock className="h-3 w-3" />
                {formatDate(scan.scannedAt)} · {formatDuration(scan.durationMs)} ·{" "}
                {scan.stats.total} findings
              </p>
            </div>
            <ChevronRight className="h-4 w-4 shrink-0 text-zinc-600" />
          </Link>
        ))}
      </div>
    </div>
  );
}
