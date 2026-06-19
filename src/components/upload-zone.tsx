"use client";

import { useCallback, useState } from "react";
import { Shield, Upload, FileArchive } from "lucide-react";
import { cn } from "@/lib/utils";

interface UploadZoneProps {
  onFileSelect: (file: File) => void;
  isScanning: boolean;
  scannerReady?: boolean;
}

export function UploadZone({ onFileSelect, isScanning, scannerReady }: UploadZoneProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleFile = useCallback(
    (file: File) => {
      if (!file.name.endsWith(".apk")) {
        alert("Please upload a valid .apk file");
        return;
      }
      onFileSelect(file);
    },
    [onFileSelect],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={onDrop}
      className={cn(
        "relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed px-8 py-16 transition-all",
        isDragging
          ? "border-emerald-400 bg-emerald-500/10"
          : "border-zinc-700 bg-zinc-900/50 hover:border-zinc-500",
        isScanning && "pointer-events-none opacity-60",
      )}
    >
      <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-emerald-500/10 ring-1 ring-emerald-500/20">
        {isDragging ? (
          <FileArchive className="h-8 w-8 text-emerald-400" />
        ) : (
          <Upload className="h-8 w-8 text-emerald-400" />
        )}
      </div>

      <h2 className="mb-2 text-xl font-semibold text-zinc-100">
        Drop your APK here
      </h2>
      <p className="mb-6 max-w-md text-center text-sm text-zinc-400">
        {scannerReady
          ? "Full APKHunt-style scan: dex2jar → JADX decompile → grep MASVS rules on Java source."
          : "Upload an APK. Start the Go scanner (docker compose up) for full JADX analysis."}
      </p>

      <label className="cursor-pointer">
        <input
          type="file"
          accept=".apk"
          className="hidden"
          disabled={isScanning}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />
        <span className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-5 py-2.5 text-sm font-medium text-white transition hover:bg-emerald-500">
          <Shield className="h-4 w-4" />
          Select APK file
        </span>
      </label>

      <p className="mt-4 text-xs text-zinc-500">Supports .apk files up to 200 MB</p>
    </div>
  );
}
