import type { ReconResult, Secret, VerifyStatus } from "@/lib/scanner/types";
import {
  Globe,
  KeyRound,
  Database,
  Server,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Lock,
} from "lucide-react";

function VerifyBadge({ status }: { status?: VerifyStatus }) {
  switch (status) {
    case "live":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[11px] font-semibold text-red-300">
          <ShieldAlert className="h-3 w-3" /> VERIFIED LIVE
        </span>
      );
    case "expired":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] font-semibold text-amber-300">
          <Lock className="h-3 w-3" /> Expired
        </span>
      );
    case "invalid":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-zinc-600 bg-zinc-800 px-2 py-0.5 text-[11px] font-semibold text-zinc-400">
          <ShieldCheck className="h-3 w-3" /> Not exploitable
        </span>
      );
    case "skipped":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-zinc-700 bg-zinc-800/60 px-2 py-0.5 text-[11px] font-medium text-zinc-500">
          <ShieldQuestion className="h-3 w-3" /> Manual check
        </span>
      );
    case "error":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-zinc-700 bg-zinc-800/60 px-2 py-0.5 text-[11px] font-medium text-zinc-500">
          Check failed
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-zinc-700 bg-zinc-800/60 px-2 py-0.5 text-[11px] font-medium text-zinc-500">
          Not tested
        </span>
      );
  }
}

function SecretRow({ secret }: { secret: Secret }) {
  const live = secret.verified === "live" && secret.reportable;
  return (
    <li
      className={`rounded-lg border p-3 ${
        live
          ? "border-red-500/40 bg-red-500/5"
          : "border-zinc-800 bg-zinc-900/60"
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <KeyRound className={`h-4 w-4 ${live ? "text-red-400" : "text-zinc-500"}`} />
          <span className="text-sm font-medium text-zinc-200">{secret.type}</span>
          <code className="rounded bg-zinc-800 px-1.5 py-0.5 font-mono text-xs text-zinc-400">
            {secret.redacted}
          </code>
        </div>
        <VerifyBadge status={secret.verified} />
      </div>
      {secret.verifyNote && (
        <p className={`mt-2 text-xs ${live ? "text-red-300" : "text-zinc-500"}`}>
          {secret.verifyNote}
        </p>
      )}
      {secret.file && (
        <p className="mt-1 font-mono text-[11px] text-zinc-600">{secret.file}</p>
      )}
    </li>
  );
}

function ListBlock({
  title,
  icon: Icon,
  items,
  mono = true,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  items: string[];
  mono?: boolean;
}) {
  if (!items || items.length === 0) return null;
  return (
    <div>
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-zinc-500">
        <Icon className="h-3.5 w-3.5" /> {title} ({items.length})
      </h4>
      <ul className="flex flex-wrap gap-1.5">
        {items.map((it) => (
          <li
            key={it}
            className={`rounded bg-zinc-800/80 px-2 py-1 text-xs text-zinc-300 ${
              mono ? "font-mono" : ""
            }`}
          >
            {it}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ReconPanel({ recon }: { recon: ReconResult }) {
  const hasAnything =
    recon.endpoints.length > 0 ||
    recon.hosts.length > 0 ||
    recon.secrets.length > 0 ||
    recon.s3Buckets.length > 0 ||
    recon.firebaseDbs.length > 0;

  if (!hasAnything) return null;

  const liveCount = recon.secrets.filter(
    (s) => s.verified === "live" && s.reportable,
  ).length;

  return (
    <div className="mt-8 rounded-xl border border-zinc-800 bg-zinc-900/80 p-6">
      <div className="mb-5 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-zinc-400">
          <Server className="h-4 w-4" /> Backend Attack Surface
        </h3>
        {recon.secretsTested && (
          <span className="text-xs text-zinc-500">
            {liveCount > 0 ? (
              <span className="font-semibold text-red-400">
                {liveCount} live secret{liveCount > 1 ? "s" : ""} confirmed
              </span>
            ) : (
              "Secrets verified — none live"
            )}
          </span>
        )}
      </div>

      {recon.secrets.length > 0 && (
        <div className="mb-6">
          <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-zinc-500">
            <KeyRound className="h-3.5 w-3.5" /> Discovered Secrets ({recon.secrets.length})
          </h4>
          <ul className="space-y-2">
            {recon.secrets.map((s, i) => (
              <SecretRow key={`${s.type}-${i}`} secret={s} />
            ))}
          </ul>
          {!recon.secretsTested && (
            <p className="mt-2 text-xs text-zinc-600">
              Live verification is opt-in. Re-run with “Verify secrets” enabled to
              confirm which keys are exploitable.
            </p>
          )}
        </div>
      )}

      <div className="space-y-5">
        <ListBlock title="API Endpoints" icon={Globe} items={recon.endpoints.map((e) => e.url)} />
        <ListBlock title="Hosts" icon={Globe} items={recon.hosts} />
        <ListBlock title="S3 Buckets" icon={Database} items={recon.s3Buckets} />
        <ListBlock title="Firebase DBs" icon={Database} items={recon.firebaseDbs} />
        <ListBlock title="GraphQL" icon={Server} items={recon.graphql} />
        <ListBlock title="Auth Schemes" icon={Lock} items={recon.authSchemes} mono={false} />
      </div>
    </div>
  );
}
