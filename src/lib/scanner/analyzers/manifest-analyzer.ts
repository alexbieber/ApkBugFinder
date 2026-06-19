import type { AppInfo, Finding } from "../types";
import { parseNetworkSecurityConfig } from "../manifest";
import { getAllStrings } from "../extract";

let findingCounter = 0;

function makeFinding(
  partial: Omit<Finding, "id"> & { id?: string },
): Finding {
  findingCounter += 1;
  return { id: partial.id ?? `finding-${findingCounter}`, ...partial };
}

export function resetFindingCounter(): void {
  findingCounter = 0;
}

export function analyzeManifest(appInfo: AppInfo, manifestData?: Uint8Array): Finding[] {
  const findings: Finding[] = [];

  if (appInfo.allowBackup === true) {
    findings.push(
      makeFinding({
        title: "Application backup enabled",
        description: "android:allowBackup is set to true, allowing adb backup of app data.",
        severity: "high",
        masvs: "MASVS-STORAGE-8",
        cwe: "CWE-921",
        category: "Data Storage",
        file: "AndroidManifest.xml",
        evidence: "allowBackup=true",
        remediation:
          "Set android:allowBackup=\"false\" or configure a BackupAgent with encryption.",
      }),
    );
  }

  if (appInfo.debuggable === true) {
    findings.push(
      makeFinding({
        title: "Debuggable application",
        description: "The app is marked debuggable, enabling runtime inspection and tampering.",
        severity: "critical",
        masvs: "MASVS-RESILIENCE-2",
        cwe: "CWE-489",
        category: "Resilience",
        file: "AndroidManifest.xml",
        evidence: "debuggable=true",
        remediation: "Ensure android:debuggable=\"false\" in release builds.",
      }),
    );
  }

  if (appInfo.usesCleartextTraffic === true) {
    findings.push(
      makeFinding({
        title: "Cleartext traffic permitted",
        description: "The app allows unencrypted HTTP network communication.",
        severity: "high",
        masvs: "MASVS-NETWORK-1",
        cwe: "CWE-319",
        category: "Network",
        file: "AndroidManifest.xml",
        evidence: "usesCleartextTraffic=true",
        remediation: "Disable cleartext traffic and use HTTPS exclusively.",
      }),
    );
  }

  const dangerousPerms = appInfo.permissions.filter((p) =>
    [
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.READ_CONTACTS",
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.CAMERA",
      "android.permission.RECORD_AUDIO",
      "android.permission.READ_EXTERNAL_STORAGE",
      "android.permission.WRITE_EXTERNAL_STORAGE",
      "android.permission.READ_PHONE_STATE",
      "android.permission.SYSTEM_ALERT_WINDOW",
    ].includes(p),
  );

  if (dangerousPerms.length > 0) {
    findings.push(
      makeFinding({
        title: "Dangerous permissions declared",
        description: `App requests ${dangerousPerms.length} sensitive permission(s).`,
        severity: "medium",
        masvs: "MASVS-PLATFORM-1",
        cwe: "CWE-250",
        category: "Platform",
        file: "AndroidManifest.xml",
        evidence: dangerousPerms.slice(0, 5).join(", "),
        remediation: "Request only permissions required at runtime and document usage.",
      }),
    );
  }

  if (manifestData) {
    const strings = getAllStrings(manifestData);
    const exported = strings.filter(
      (s) => s === "exported" || s.includes("exported"),
    );
    if (exported.length > 0) {
      const hasTrue = strings.some((s, i) => s.includes("exported") && strings[i + 1] === "true");
      if (hasTrue) {
        findings.push(
          makeFinding({
            title: "Exported components detected",
            description: "One or more components are exported and accessible to other apps.",
            severity: "medium",
            masvs: "MASVS-PLATFORM-1",
            cwe: "CWE-926",
            category: "Platform",
            file: "AndroidManifest.xml",
            evidence: "exported=true on component(s)",
            remediation: "Set android:exported=\"false\" unless required; validate all intents.",
          }),
        );
      }
    }
  }

  return findings;
}

export function analyzeNetworkConfig(
  configData: Uint8Array | undefined,
): Finding[] {
  const findings: Finding[] = [];
  const config = parseNetworkSecurityConfig(configData);

  if (config.cleartextPermitted) {
    findings.push(
      makeFinding({
        title: "Network security config allows cleartext",
        description: "network_security_config.xml permits cleartext HTTP traffic.",
        severity: "high",
        masvs: "MASVS-NETWORK-1",
        cwe: "CWE-319",
        category: "Network",
        file: "res/xml/network_security_config.xml",
        evidence: "cleartextTrafficPermitted=\"true\"",
        remediation: "Remove cleartext exceptions and enforce TLS.",
      }),
    );
  }

  if (!config.hasPinning && configData) {
    findings.push(
      makeFinding({
        title: "No certificate pinning configured",
        description: "Network security config does not define a pin-set.",
        severity: "info",
        masvs: "MASVS-NETWORK-4",
        category: "Network",
        file: "res/xml/network_security_config.xml",
        remediation: "Consider certificate pinning for sensitive API endpoints.",
      }),
    );
  }

  return findings;
}

export function analyzePermissions(appInfo: AppInfo): Finding[] {
  const findings: Finding[] = [];

  if (appInfo.permissions.includes("android.permission.INTERNET") && appInfo.usesCleartextTraffic !== false) {
    findings.push(
      makeFinding({
        title: "Internet access without explicit cleartext restriction",
        description: "App has INTERNET permission; verify all endpoints use TLS.",
        severity: "low",
        masvs: "MASVS-NETWORK-1",
        category: "Network",
        remediation: "Audit all network calls and disable cleartext traffic.",
      }),
    );
  }

  return findings;
}
