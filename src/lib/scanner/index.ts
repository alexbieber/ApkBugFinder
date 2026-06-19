import type { ScanResult } from "./types";
export { scanApkViaServer, checkScannerHealth } from "./api-client";
export type { ScannerHealth } from "./api-client";

// Client-side fallback (lightweight, no JADX)
export { scanApk as scanApkClient } from "./client";

export function saveScanResult(result: ScanResult): void {
  if (typeof window === "undefined") return;
  const history = getScanHistory();
  history.unshift(result);
  localStorage.setItem("apkbugfinder-scans", JSON.stringify(history.slice(0, 20)));
}

export function getScanHistory(): ScanResult[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem("apkbugfinder-scans");
    return raw ? (JSON.parse(raw) as ScanResult[]) : [];
  } catch {
    return [];
  }
}

export function getScanById(id: string): ScanResult | undefined {
  return getScanHistory().find((s) => s.id === id);
}
