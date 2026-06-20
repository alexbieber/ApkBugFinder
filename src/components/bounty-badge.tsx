import { cn } from "@/lib/utils";

export function BountyBadge({
  impact,
  eligible,
}: {
  impact?: number;
  eligible?: boolean;
}) {
  if (!eligible || !impact || impact < 7) return null;

  const color =
    impact >= 9
      ? "border-red-500/50 bg-red-500/15 text-red-300"
      : impact >= 8
        ? "border-orange-500/50 bg-orange-500/15 text-orange-300"
        : "border-amber-500/40 bg-amber-500/10 text-amber-300";

  return (
    <span
      className={cn(
        "rounded border px-2 py-0.5 text-xs font-semibold tabular-nums",
        color,
      )}
    >
      Bounty {impact}/10
    </span>
  );
}

export function isBountyFinding(f: {
  bountyEligible?: boolean;
  impact?: number;
}): boolean {
  return Boolean(f.bountyEligible && f.impact && f.impact >= 7);
}
