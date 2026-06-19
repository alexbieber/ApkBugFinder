import type { Finding } from "../types";
import { getAllStrings } from "../extract";

let findingCounter = 1000;

function makeFinding(partial: Omit<Finding, "id">): Finding {
  findingCounter += 1;
  return { id: `secret-${findingCounter}`, ...partial };
}

const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: Finding["severity"];
}> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "AWS Secret Key", pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}/i, severity: "critical" },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/, severity: "critical" },
  { name: "Firebase URL", pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/i, severity: "high" },
  { name: "Generic API Key", pattern: /api[_-]?key\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i, severity: "high" },
  { name: "Bearer Token", pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i, severity: "high" },
  { name: "Private Key", pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, severity: "critical" },
  { name: "Hardcoded Password", pattern: /password\s*[:=]\s*['"][^'"]{4,}['"]/i, severity: "high" },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, severity: "high" },
  { name: "Slack Token", pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/, severity: "critical" },
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/, severity: "critical" },
  { name: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/, severity: "critical" },
];

export function analyzeSecrets(
  fileContents: Map<string, Uint8Array>,
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const [path, data] of fileContents) {
    if (!path.endsWith(".dex") && !path.endsWith(".xml") && !path.endsWith(".json") && !path.endsWith(".properties")) {
      continue;
    }

    const strings = getAllStrings(data);
    const combined = strings.join("\n");

    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      const match = combined.match(pattern);
      if (match) {
        const key = `${name}:${path}:${match[0].slice(0, 20)}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(
          makeFinding({
            title: `Possible ${name} exposed`,
            description: `Pattern matching ${name} found in APK resources.`,
            severity,
            masvs: "MASVS-STORAGE-14",
            cwe: "CWE-798",
            category: "Secrets",
            file: path,
            evidence: match[0].slice(0, 80) + (match[0].length > 80 ? "…" : ""),
            remediation: "Remove hardcoded secrets; use Android Keystore or remote config with access controls.",
          }),
        );
      }
    }
  }

  return findings;
}

export function analyzeLogging(fileContents: Map<string, Uint8Array>): Finding[] {
  const findings: Finding[] = [];
  const sensitivePatterns = [
    /Log\.[deiwv]\([^)]*password/i,
    /Log\.[deiwv]\([^)]*token/i,
    /Log\.[deiwv]\([^)]*secret/i,
    /Log\.[deiwv]\([^)]*apiKey/i,
    /System\.out\.print[^)]*password/i,
  ];

  for (const [path, data] of fileContents) {
    if (!path.endsWith(".dex")) continue;
    const text = getAllStrings(data).join("\n");

    for (const pattern of sensitivePatterns) {
      const match = text.match(pattern);
      if (match) {
        findings.push(
          makeFinding({
            title: "Sensitive data in logs",
            description: "Logging calls may expose sensitive information.",
            severity: "medium",
            masvs: "MASVS-STORAGE-3",
            cwe: "CWE-532",
            category: "Data Storage",
            file: path,
            evidence: match[0].slice(0, 100),
            remediation: "Remove sensitive data from log statements in production builds.",
          }),
        );
        break;
      }
    }
  }

  return findings;
}
