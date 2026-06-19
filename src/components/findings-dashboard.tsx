"use client";

import { useMemo, useState } from "react";
import type { Finding, ScanResult, Severity } from "@/lib/scanner/types";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import { ChevronDown, Search, Filter } from "lucide-react";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function StatCard({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-4">
      <p className="text-xs uppercase tracking-wider text-zinc-500">{label}</p>
      <p className={cn("mt-1 text-3xl font-bold tabular-nums", color)}>{count}</p>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 transition hover:border-zinc-700">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-4 p-4 text-left"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="min-w-0 flex-1">
          <h4 className="font-medium text-zinc-100">{finding.title}</h4>
          <p className="mt-1 text-sm text-zinc-400">{finding.description}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs text-emerald-400">
              {finding.masvs}
            </span>
            {finding.cwe && (
              <span className="rounded bg-zinc-800 px-2 py-0.5 font-mono text-xs text-zinc-400">
                {finding.cwe}
              </span>
            )}
            <span className="text-xs text-zinc-500">{finding.category}</span>
          </div>
        </div>
        <ChevronDown
          className={cn(
            "h-5 w-5 shrink-0 text-zinc-500 transition",
            expanded && "rotate-180",
          )}
        />
      </button>

      {expanded && (
        <div className="border-t border-zinc-800 px-4 pb-4 pt-3">
          {finding.file && (
            <div className="mb-3">
              <p className="text-xs text-zinc-500">Location</p>
              <p className="font-mono text-sm text-zinc-300">{finding.file}</p>
            </div>
          )}
          {finding.evidence && (
            <div className="mb-3">
              <p className="text-xs text-zinc-500">Evidence</p>
              <pre className="mt-1 overflow-x-auto rounded-lg bg-zinc-950 p-3 font-mono text-xs text-amber-300">
                {finding.evidence}
              </pre>
            </div>
          )}
          <div>
            <p className="text-xs text-zinc-500">Remediation</p>
            <p className="mt-1 text-sm text-zinc-300">{finding.remediation}</p>
          </div>
          {finding.reference && (
            <div className="mt-3">
              <a
                href={finding.reference}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-emerald-400 hover:underline"
              >
                MASVS reference →
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingsDashboard({ result }: { result: ScanResult }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");

  const filtered = useMemo(() => {
    return result.findings.filter((f) => {
      const matchesSearch =
        !search ||
        f.title.toLowerCase().includes(search.toLowerCase()) ||
        f.masvs.toLowerCase().includes(search.toLowerCase()) ||
        f.category.toLowerCase().includes(search.toLowerCase());
      const matchesSeverity = severityFilter === "all" || f.severity === severityFilter;
      return matchesSearch && matchesSeverity;
    });
  }, [result.findings, search, severityFilter]);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Total" count={result.stats.total} color="text-zinc-100" />
        <StatCard label="Critical" count={result.stats.critical} color="text-red-400" />
        <StatCard label="High" count={result.stats.high} color="text-orange-400" />
        <StatCard label="Medium" count={result.stats.medium} color="text-yellow-400" />
        <StatCard label="Low" count={result.stats.low} color="text-blue-400" />
        <StatCard label="Info" count={result.stats.info} color="text-zinc-400" />
      </div>

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            placeholder="Search findings…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-zinc-800 bg-zinc-900 py-2 pl-10 pr-4 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-1 focus:ring-emerald-500/30"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-zinc-500" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Severity | "all")}
            className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:border-emerald-500/50 focus:outline-none"
          >
            <option value="all">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="space-y-3">
        {filtered.length === 0 ? (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 py-12 text-center">
            <p className="text-zinc-400">
              {result.findings.length === 0
                ? "No security issues detected — great job!"
                : "No findings match your filters."}
            </p>
          </div>
        ) : (
          filtered.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))
        )}
      </div>
    </div>
  );
}
