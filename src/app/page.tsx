"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { UploadZone } from "@/components/upload-zone";
import { ScanProgressBar } from "@/components/scan-progress";
import { ScanHistory } from "@/components/scan-history";
import { ScannerStatus } from "@/components/scanner-status";
import {
  scanApkViaServer,
  scanApkClient,
  checkScannerHealth,
  saveScanResult,
  getScanHistory,
} from "@/lib/scanner";
import type { ScanProgress, ScanResult } from "@/lib/scanner/types";
import type { ScannerHealth } from "@/lib/scanner/api-client";
import { Zap, Server, Layers } from "lucide-react";

const features = [
  {
    icon: Server,
    title: "APKHunt-grade engine",
    description: "JADX + dex2jar decompilation with 70+ MASVS grep rules on Java source.",
  },
  {
    icon: Layers,
    title: "Full MASVS coverage",
    description: "V1–V8: storage, crypto, auth, network, platform, code, resilience.",
  },
  {
    icon: Zap,
    title: "Advanced on top",
    description: "Extra secret detection (AWS, Stripe, JWT), SARIF-ready JSON export.",
  },
];

export default function HomePage() {
  const router = useRouter();
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [health, setHealth] = useState<ScannerHealth | null>(null);
  const [verifySecrets, setVerifySecrets] = useState(false);

  useEffect(() => {
    setHistory(getScanHistory());
    checkScannerHealth().then(setHealth);
  }, []);

  const handleFileSelect = useCallback(
    async (file: File) => {
      setIsScanning(true);
      setProgress({ stage: "extracting", progress: 5, message: "Starting scan…" });

      try {
        let result: ScanResult;
        const scannerReady = health?.status === "ok";

        if (scannerReady) {
          result = await scanApkViaServer(file, setProgress, verifySecrets);
        } else {
          setProgress({
            stage: "analyzing",
            progress: 20,
            message: "Scanner offline — using lightweight client fallback…",
          });
          result = await scanApkClient(file, setProgress);
        }

        saveScanResult(result);
        router.push(`/scan/${result.id}`);
      } catch (err) {
        setProgress({
          stage: "error",
          progress: 0,
          message: err instanceof Error ? err.message : "Scan failed",
        });
        setIsScanning(false);
      }
    },
    [router, health, verifySecrets],
  );

  return (
    <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
      <div className="mb-8 flex justify-center">
        <ScannerStatus health={health} />
      </div>

      <div className="mb-12 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-zinc-50 sm:text-5xl">
          Find security bugs in{" "}
          <span className="bg-gradient-to-r from-emerald-400 to-teal-300 bg-clip-text text-transparent">
            Android APKs
          </span>
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-lg text-zinc-400">
          APKHunt-level OWASP MASVS static analysis with JADX decompilation — plus
          advanced secret detection and a modern web UI.
        </p>
      </div>

      <div className="mx-auto max-w-2xl">
        <UploadZone onFileSelect={handleFileSelect} isScanning={isScanning} scannerReady={health?.status === "ok"} />
        {health?.verifyAllowed && (
          <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900/40 p-4">
            <input
              type="checkbox"
              checked={verifySecrets}
              onChange={(e) => setVerifySecrets(e.target.checked)}
              disabled={isScanning}
              className="mt-0.5 h-4 w-4 accent-emerald-500"
            />
            <span className="text-sm">
              <span className="font-medium text-zinc-200">Verify secrets (live)</span>
              <span className="mt-0.5 block text-xs text-zinc-500">
                Runs opt-in, read-only liveness checks on discovered API keys and tokens.
                Makes outbound network requests to providers (Google, Stripe, GitHub, etc.).
                Only enable on APKs you are authorized to test.
              </span>
            </span>
          </label>
        )}
        {progress && isScanning && (
          <div className="mt-6">
            <ScanProgressBar progress={progress} />
          </div>
        )}
      </div>

      <div className="mt-16 grid gap-6 sm:grid-cols-3">
        {features.map(({ icon: Icon, title, description }) => (
          <div
            key={title}
            className="rounded-xl border border-zinc-800/80 bg-zinc-900/40 p-6"
          >
            <Icon className="mb-3 h-6 w-6 text-emerald-400" />
            <h3 className="font-semibold text-zinc-200">{title}</h3>
            <p className="mt-1 text-sm text-zinc-500">{description}</p>
          </div>
        ))}
      </div>

      <ScanHistory scans={history} />
    </div>
  );
}
