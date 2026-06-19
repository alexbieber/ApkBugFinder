import JSZip from "jszip";

export async function extractApkEntries(file: File): Promise<Map<string, Uint8Array>> {
  const zip = await JSZip.loadAsync(await file.arrayBuffer());
  const entries = new Map<string, Uint8Array>();

  await Promise.all(
    Object.keys(zip.files).map(async (path) => {
      const entry = zip.files[path];
      if (!entry.dir) {
        entries.set(path, await entry.async("uint8array"));
      }
    }),
  );

  return entries;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hash));
}

export function extractStrings(data: Uint8Array, minLength = 4): string[] {
  const strings: string[] = [];
  let current = "";

  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        strings.push(current);
      }
      current = "";
    }
  }

  if (current.length >= minLength) {
    strings.push(current);
  }

  return strings;
}

export function readUtf16Strings(data: Uint8Array, minLength = 4): string[] {
  const strings: string[] = [];

  for (let i = 0; i < data.length - 1; i += 2) {
    let current = "";
    let j = i;

    while (j < data.length - 1) {
      const code = data[j] | (data[j + 1] << 8);
      if (code >= 32 && code <= 126) {
        current += String.fromCharCode(code);
        j += 2;
      } else {
        break;
      }
    }

    if (current.length >= minLength) {
      strings.push(current);
    }
  }

  return strings;
}

export function getAllStrings(data: Uint8Array): string[] {
  return [...new Set([...extractStrings(data), ...readUtf16Strings(data)])];
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
