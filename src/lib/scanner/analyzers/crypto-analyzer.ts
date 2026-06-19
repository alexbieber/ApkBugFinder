import type { Finding } from "../types";
import { getAllStrings } from "../extract";

let findingCounter = 2000;

function makeFinding(partial: Omit<Finding, "id">): Finding {
  findingCounter += 1;
  return { id: `crypto-${findingCounter}`, ...partial };
}

const WEAK_ALGORITHMS = [
  { pattern: /DES\/ECB/i, name: "DES/ECB", severity: "high" as const },
  { pattern: /DESede\/ECB/i, name: "3DES/ECB", severity: "high" as const },
  { pattern: /AES\/ECB/i, name: "AES/ECB", severity: "medium" as const },
  { pattern: /RC4/i, name: "RC4", severity: "high" as const },
  { pattern: /Blowfish/i, name: "Blowfish", severity: "medium" as const },
  { pattern: /MD5/i, name: "MD5", severity: "medium" as const },
  { pattern: /SHA-?1(?!024)/i, name: "SHA-1", severity: "medium" as const },
  { pattern: /RSA\/ECB\/NoPadding/i, name: "RSA/ECB/NoPadding", severity: "high" as const },
];

const INSECURE_RANDOM = [
  /java\.util\.Random/,
  /Math\.random\(\)/,
];

export function analyzeCrypto(fileContents: Map<string, Uint8Array>): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const [path, data] of fileContents) {
    if (!path.endsWith(".dex")) continue;
    const text = getAllStrings(data).join("\n");

    for (const { pattern, name, severity } of WEAK_ALGORITHMS) {
      if (pattern.test(text)) {
        const key = `${name}:${path}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(
          makeFinding({
            title: `Weak cryptography: ${name}`,
            description: `Use of deprecated or insecure algorithm ${name} detected.`,
            severity,
            masvs: "MASVS-CRYPTO-4",
            cwe: "CWE-327",
            category: "Cryptography",
            file: path,
            evidence: name,
            remediation: `Replace ${name} with AES/GCM and SHA-256 or stronger algorithms.`,
          }),
        );
      }
    }

    for (const pattern of INSECURE_RANDOM) {
      if (pattern.test(text)) {
        const key = `random:${path}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(
          makeFinding({
            title: "Insecure random number generator",
            description: "Use of predictable PRNG for security-sensitive operations.",
            severity: "medium",
            masvs: "MASVS-CRYPTO-6",
            cwe: "CWE-330",
            category: "Cryptography",
            file: path,
            evidence: pattern.source,
            remediation: "Use SecureRandom or Android Keystore for cryptographic operations.",
          }),
        );
      }
    }
  }

  return findings;
}

export function analyzeWebView(fileContents: Map<string, Uint8Array>): Finding[] {
  const findings: Finding[] = [];

  for (const [path, data] of fileContents) {
    if (!path.endsWith(".dex")) continue;
    const text = getAllStrings(data).join("\n");

    if (/setJavaScriptEnabled\s*\(\s*true\s*\)/i.test(text) || /setJavaScriptEnabled\(Z\)V/.test(text)) {
      findings.push(
        makeFinding({
          title: "JavaScript enabled in WebView",
          description: "WebView has JavaScript enabled, increasing XSS risk.",
          severity: "medium",
          masvs: "MASVS-PLATFORM-7",
          cwe: "CWE-79",
          category: "Platform",
          file: path,
          evidence: "setJavaScriptEnabled(true)",
          remediation: "Disable JavaScript unless required; validate all loaded URLs.",
        }),
      );
    }

    if (/addJavascriptInterface/i.test(text)) {
      findings.push(
        makeFinding({
          title: "JavaScript interface exposed in WebView",
          description: "@JavascriptInterface bridges native code to JavaScript.",
          severity: "high",
          masvs: "MASVS-PLATFORM-7",
          cwe: "CWE-749",
          category: "Platform",
          file: path,
          evidence: "addJavascriptInterface",
          remediation: "Avoid JS bridges; if required, use @JavascriptInterface only on API 17+ with strict URL allowlists.",
        }),
      );
    }

    if (/setAllowFileAccess\s*\(\s*true\s*\)/i.test(text)) {
      findings.push(
        makeFinding({
          title: "WebView file access enabled",
          description: "WebView allows file:// URI access.",
          severity: "medium",
          masvs: "MASVS-PLATFORM-7",
          cwe: "CWE-200",
          category: "Platform",
          file: path,
          evidence: "setAllowFileAccess(true)",
          remediation: "Disable file access in WebView settings.",
        }),
      );
    }
  }

  return findings;
}

export function analyzeStorage(fileContents: Map<string, Uint8Array>): Finding[] {
  const findings: Finding[] = [];
  const storageSinks = [
    { pattern: /SharedPreferences/, title: "SharedPreferences usage", masvs: "MASVS-STORAGE-2" },
    { pattern: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/, title: "World-readable/writable storage", masvs: "MASVS-STORAGE-2", severity: "high" as const },
    { pattern: /openFileOutput.*MODE_PRIVATE/i, title: "Internal file storage", masvs: "MASVS-STORAGE-2", severity: "info" as const },
    { pattern: /SQLiteDatabase|RoomDatabase/, title: "Local database usage", masvs: "MASVS-STORAGE-2", severity: "info" as const },
    { pattern: /getExternalStorageDirectory|Environment\.DIRECTORY/, title: "External storage access", masvs: "MASVS-STORAGE-2", severity: "medium" as const },
  ];

  for (const [path, data] of fileContents) {
    if (!path.endsWith(".dex")) continue;
    const text = getAllStrings(data).join("\n");

    for (const sink of storageSinks) {
      if (sink.pattern.test(text)) {
        findings.push(
          makeFinding({
            title: sink.title,
            description: `Detected ${sink.title.toLowerCase()} — verify sensitive data is encrypted.`,
            severity: sink.severity ?? "low",
            masvs: sink.masvs,
            cwe: "CWE-922",
            category: "Data Storage",
            file: path,
            evidence: sink.pattern.source,
            remediation: "Encrypt sensitive data at rest using Android Keystore.",
          }),
        );
        break;
      }
    }
  }

  return findings;
}
