export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  masvs: string;
  cwe?: string;
  category: string;
  evidence?: string;
  file?: string;
  remediation: string;
  reference?: string;
}

export interface AppInfo {
  packageName?: string;
  versionName?: string;
  versionCode?: string;
  minSdk?: string;
  targetSdk?: string;
  permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  debuggable?: boolean;
  allowBackup?: boolean;
  usesCleartextTraffic?: boolean;
  fileName: string;
  fileSize: number;
  md5?: string;
  sha256?: string;
  componentSummary?: {
    exportedActivities: number;
    exportedProviders: number;
    exportedReceivers: number;
    exportedServices: number;
  };
}

export interface ScanResult {
  id: string;
  scannedAt: string;
  durationMs: number;
  engine?: string;
  appInfo: AppInfo;
  findings: Finding[];
  stats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

export interface ScanProgress {
  stage: "extracting" | "analyzing" | "complete" | "error";
  progress: number;
  message: string;
}
