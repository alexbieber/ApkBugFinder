import type { AppInfo } from "@/lib/scanner/types";
import { formatBytes } from "@/lib/scanner/extract";
import { Package, Hash, Layers, Shield } from "lucide-react";

export function AppInfoPanel({ appInfo }: { appInfo: AppInfo }) {
  const rows = [
    { label: "Package", value: appInfo.packageName ?? "Unknown", icon: Package },
    { label: "Version", value: appInfo.versionName ?? "—", icon: Layers },
    { label: "Min SDK", value: appInfo.minSdk ?? "—", icon: Shield },
    { label: "Target SDK", value: appInfo.targetSdk ?? "—", icon: Shield },
    { label: "File size", value: formatBytes(appInfo.fileSize), icon: Hash },
    { label: "SHA-256", value: appInfo.sha256 ? `${appInfo.sha256.slice(0, 16)}…` : "—", icon: Hash },
  ];

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-6">
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-zinc-400">
        App Overview
      </h3>
      <dl className="space-y-3">
        {rows.map(({ label, value, icon: Icon }) => (
          <div key={label} className="flex items-start gap-3">
            <Icon className="mt-0.5 h-4 w-4 shrink-0 text-zinc-500" />
            <div className="min-w-0 flex-1">
              <dt className="text-xs text-zinc-500">{label}</dt>
              <dd className="truncate font-mono text-sm text-zinc-200">{value}</dd>
            </div>
          </div>
        ))}
      </dl>

      {appInfo.componentSummary && (
        <div className="mt-6 border-t border-zinc-800 pt-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            Exported Components
          </h4>
          <dl className="grid grid-cols-2 gap-2 text-xs">
            <div><dt className="text-zinc-500">Activities</dt><dd className="font-mono text-zinc-300">{appInfo.componentSummary.exportedActivities}</dd></div>
            <div><dt className="text-zinc-500">Services</dt><dd className="font-mono text-zinc-300">{appInfo.componentSummary.exportedServices}</dd></div>
            <div><dt className="text-zinc-500">Receivers</dt><dd className="font-mono text-zinc-300">{appInfo.componentSummary.exportedReceivers}</dd></div>
            <div><dt className="text-zinc-500">Providers</dt><dd className="font-mono text-zinc-300">{appInfo.componentSummary.exportedProviders}</dd></div>
          </dl>
        </div>
      )}

      {appInfo.permissions.length > 0 && (
        <div className="mt-6 border-t border-zinc-800 pt-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            Permissions ({appInfo.permissions.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {appInfo.permissions.slice(0, 8).map((perm) => (
              <span
                key={perm}
                className="rounded-md bg-zinc-800 px-2 py-0.5 font-mono text-xs text-zinc-400"
              >
                {perm.replace("android.permission.", "")}
              </span>
            ))}
            {appInfo.permissions.length > 8 && (
              <span className="text-xs text-zinc-500">
                +{appInfo.permissions.length - 8} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
