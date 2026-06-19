import Link from "next/link";
import { Shield } from "lucide-react";

export function Header() {
  return (
    <header className="border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur-sm">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/20">
            <Shield className="h-5 w-5 text-emerald-400" />
          </div>
          <div>
            <span className="text-lg font-bold text-zinc-100">Apkbugfinder</span>
            <span className="ml-2 hidden text-xs text-zinc-500 sm:inline">
              OWASP MASVS Scanner
            </span>
          </div>
        </Link>
        <nav className="flex items-center gap-4">
          <a
            href="https://mobile-security.gitbook.io/masvs/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-zinc-400 transition hover:text-zinc-200"
          >
            MASVS Docs
          </a>
          <a
            href="https://github.com/alexbieber/ApkBugFinder"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 transition hover:border-zinc-600 hover:bg-zinc-900"
          >
            GitHub
          </a>
        </nav>
      </div>
    </header>
  );
}
