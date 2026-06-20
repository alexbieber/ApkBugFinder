export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence =
  | "confirmed"
  | "high"
  | "medium"
  | "low"
  | "informational";

export type FindingScope =
  | "manifest"
  | "app-code"
  | "resource"
  | "library"
  | "hygiene";

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence?: Confidence;
  scope?: FindingScope;
  impact?: number;
  bountyEligible?: boolean;
  attackSurface?: string;
  exploitHint?: string;
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

export type VerifyStatus =
  | ""
  | "live"
  | "invalid"
  | "error"
  | "skipped"
  | "expired";

export interface Secret {
  type: string;
  provider: string;
  redacted: string;
  file?: string;
  severity: Severity;
  verified?: VerifyStatus;
  verifyNote?: string;
  reportable: boolean;
}

export interface Endpoint {
  url: string;
  host: string;
  scheme: string;
  file?: string;
}

export interface ReconResult {
  endpoints: Endpoint[];
  hosts: string[];
  s3Buckets: string[];
  firebaseDbs: string[];
  graphql: string[];
  secrets: Secret[];
  authSchemes: string[];
  secretsTested: boolean;
}

export interface ScanResult {
  id: string;
  scannedAt: string;
  durationMs: number;
  engine?: string;
  appInfo: AppInfo;
  findings: Finding[];
  recon?: ReconResult;
  stats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    actionable?: number;
    confirmed?: number;
    bountyEligible?: number;
    bountyCritical?: number;
    liveSecrets?: number;
  };
}

export interface ScanProgress {
  stage: "extracting" | "analyzing" | "complete" | "error";
  progress: number;
  message: string;
}
