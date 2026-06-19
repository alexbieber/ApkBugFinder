import type { ScanProgress, ScanResult } from "./types";
import { extractApkEntries, sha256Hex } from "./extract";
import { parseManifest } from "./manifest";
import { resetFindingCounter, analyzeManifest, analyzeNetworkConfig, analyzePermissions } from "./analyzers/manifest-analyzer";
import { analyzeSecrets, analyzeLogging } from "./analyzers/secrets-analyzer";
import { analyzeCrypto, analyzeWebView, analyzeStorage } from "./analyzers/crypto-analyzer";

function computeStats(findings: ScanResult["findings"]) {
  return {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
    total: findings.length,
  };
}

function sortFindings(findings: ScanResult["findings"]) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
}

/** Lightweight browser-only scan (fallback when Go scanner is offline). */
export async function scanApk(
  file: File,
  onProgress?: (progress: ScanProgress) => void,
): Promise<ScanResult> {
  const start = performance.now();
  resetFindingCounter();

  onProgress?.({ stage: "extracting", progress: 10, message: "Extracting APK contents (client fallback)…" });

  const buffer = await file.arrayBuffer();
  const hash = await sha256Hex(buffer);
  const entries = await extractApkEntries(file);

  onProgress?.({ stage: "analyzing", progress: 40, message: "Parsing AndroidManifest…" });

  const manifestData = entries.get("AndroidManifest.xml");
  const appInfo = parseManifest(manifestData, file.name, file.size);
  appInfo.sha256 = hash;

  onProgress?.({ stage: "analyzing", progress: 55, message: "Running basic MASVS checks…" });

  const networkConfigPath = [...entries.keys()].find((k) =>
    k.includes("network_security_config"),
  );
  const networkConfigData = networkConfigPath ? entries.get(networkConfigPath) : undefined;

  const findings = sortFindings([
    ...analyzeManifest(appInfo, manifestData),
    ...analyzePermissions(appInfo),
    ...analyzeNetworkConfig(networkConfigData),
    ...analyzeSecrets(entries),
    ...analyzeLogging(entries),
    ...analyzeCrypto(entries),
    ...analyzeWebView(entries),
    ...analyzeStorage(entries),
  ]);

  onProgress?.({ stage: "complete", progress: 100, message: "Scan complete" });

  return {
    id: crypto.randomUUID(),
    scannedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - start),
    engine: "client-fallback",
    appInfo,
    findings,
    stats: computeStats(findings),
  };
}
