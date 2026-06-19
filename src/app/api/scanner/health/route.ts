import { NextResponse } from "next/server";

const SCANNER_URL = process.env.SCANNER_API_URL ?? "http://localhost:8080";

export async function GET() {
  try {
    const res = await fetch(`${SCANNER_URL}/api/v1/health`, { cache: "no-store" });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { status: "offline", engine: "apkbugfinder-scanner", missing: ["Scanner not reachable"] },
      { status: 503 },
    );
  }
}
