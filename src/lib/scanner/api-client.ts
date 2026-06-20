import type { ScanProgress, ScanResult } from "./types";

export interface ScannerHealth {
  status: string;
  engine: string;
  version: string;
  missing?: string[];
  verifyAllowed?: boolean;
}

export async function checkScannerHealth(): Promise<ScannerHealth | null> {
  try {
    const res = await fetch("/api/scanner/health", { cache: "no-store" });
    if (!res.ok) return null;
    return (await res.json()) as ScannerHealth;
  } catch {
    return null;
  }
}

export async function scanApkViaServer(
  file: File,
  onProgress?: (progress: ScanProgress) => void,
  verifySecrets = false,
): Promise<ScanResult> {
  onProgress?.({ stage: "extracting", progress: 10, message: "Uploading APK to scanner…" });

  const form = new FormData();
  form.append("apk", file);
  if (verifySecrets) {
    form.append("verify", "true");
  }

  onProgress?.({ stage: "analyzing", progress: 30, message: "Decompiling with JADX + dex2jar…" });

  const res = await fetch("/api/scan", {
    method: "POST",
    body: form,
  });

  onProgress?.({ stage: "analyzing", progress: 70, message: "Running MASVS rules on decompiled source…" });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error ?? "Scan failed");
  }

  onProgress?.({ stage: "complete", progress: 100, message: "Scan complete" });

  const result = data as ScanResult;
  if (!result.appInfo.fileName) {
    result.appInfo.fileName = file.name;
  }
  if (!result.appInfo.fileSize) {
    result.appInfo.fileSize = file.size;
  }
  return result;
}
