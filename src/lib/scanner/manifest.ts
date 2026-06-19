import type { AppInfo } from "./types";
import { getAllStrings } from "./extract";

function findStringValue(strings: string[], key: string): string | undefined {
  const idx = strings.findIndex((s) => s === key || s.includes(key));
  if (idx === -1) return undefined;

  for (let i = idx + 1; i < Math.min(idx + 5, strings.length); i++) {
    const val = strings[i];
    if (val && !val.startsWith("android.") && val.length > 1 && val.length < 200) {
      return val;
    }
  }
  return undefined;
}

function extractPermissions(strings: string[]): string[] {
  return [...new Set(strings.filter((s) => s.startsWith("android.permission.")))];
}

function extractComponents(strings: string[], marker: string): string[] {
  const components: string[] = [];
  for (let i = 0; i < strings.length; i++) {
    if (strings[i] === marker || strings[i].endsWith(marker)) {
      const name = strings[i + 1];
      if (name && name.includes(".") && !name.startsWith("android.")) {
        components.push(name);
      }
    }
  }
  return [...new Set(components)];
}

function parseManifestBoolean(strings: string[], attr: string): boolean | undefined {
  const idx = strings.findIndex((s) => s === attr || s.includes(attr));
  if (idx === -1) return undefined;

  for (let i = idx; i < Math.min(idx + 4, strings.length); i++) {
    if (strings[i] === "true") return true;
    if (strings[i] === "false") return false;
  }
  return undefined;
}

export function parseManifest(
  manifestData: Uint8Array | undefined,
  fileName: string,
  fileSize: number,
): AppInfo {
  const strings = manifestData ? getAllStrings(manifestData) : [];

  const packageName =
    findStringValue(strings, "package") ??
    strings.find((s) => /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(s) && s.length > 5);

  return {
    fileName,
    fileSize,
    packageName,
    versionName: findStringValue(strings, "versionName"),
    versionCode: findStringValue(strings, "versionCode"),
    minSdk: findStringValue(strings, "minSdkVersion"),
    targetSdk: findStringValue(strings, "targetSdkVersion"),
    permissions: extractPermissions(strings),
    activities: extractComponents(strings, "activity"),
    services: extractComponents(strings, "service"),
    receivers: extractComponents(strings, "receiver"),
    providers: extractComponents(strings, "provider"),
    debuggable: parseManifestBoolean(strings, "debuggable"),
    allowBackup: parseManifestBoolean(strings, "allowBackup"),
    usesCleartextTraffic: parseManifestBoolean(strings, "usesCleartextTraffic"),
  };
}

export function parseNetworkSecurityConfig(data: Uint8Array | undefined): {
  cleartextPermitted: boolean;
  hasPinning: boolean;
} {
  if (!data) return { cleartextPermitted: false, hasPinning: false };
  const text = new TextDecoder("utf-8", { fatal: false }).decode(data);
  return {
    cleartextPermitted: /cleartextTrafficPermitted\s*=\s*"true"/i.test(text),
    hasPinning: /<pin-set/i.test(text),
  };
}
