"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { AppInfoPanel } from "@/components/app-info-panel";
import { FindingsDashboard } from "@/components/findings-dashboard";
import { ReconPanel } from "@/components/recon-panel";
import { getScanById } from "@/lib/scanner";
import type { ScanResult } from "@/lib/scanner/types";
import { formatDate, formatDuration } from "@/lib/utils";
import { ArrowLeft, Download, Clock } from "lucide-react";

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    const id = params.id as string;
    const scan = getScanById(id);
    if (!scan) {
      router.push("/");
      return;
    }
    setResult(scan);
  }, [params.id, router]);

  if (!result) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
      </div>
    );
  }

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `apkbugfinder-${result.appInfo.fileName.replace(".apk", "")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
      <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <Link
            href="/"
            className="mb-3 inline-flex items-center gap-1.5 text-sm text-zinc-500 transition hover:text-zinc-300"
          >
            <ArrowLeft className="h-4 w-4" />
            New scan
          </Link>
          <h1 className="text-2xl font-bold text-zinc-100">
            {result.appInfo.fileName}
          </h1>
          <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-zinc-500">
            <Clock className="h-3.5 w-3.5" />
            {formatDate(result.scannedAt)} · {formatDuration(result.durationMs)}
            {result.engine && (
              <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs text-emerald-400">
                {result.engine}
              </span>
            )}
          </p>
        </div>
        <button
          type="button"
          onClick={exportJson}
          className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm text-zinc-300 transition hover:border-zinc-600 hover:bg-zinc-800"
        >
          <Download className="h-4 w-4" />
          Export JSON
        </button>
      </div>

      <div className="grid gap-8 lg:grid-cols-[280px_1fr]">
        <aside className="lg:sticky lg:top-8 lg:self-start">
          <AppInfoPanel appInfo={result.appInfo} />
        </aside>
        <section>
          <FindingsDashboard result={result} />
          {result.recon && <ReconPanel recon={result.recon} />}
        </section>
      </div>
    </div>
  );
}
