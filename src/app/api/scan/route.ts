import { NextRequest, NextResponse } from "next/server";

const SCANNER_URL = process.env.SCANNER_API_URL ?? "http://localhost:8080";

export async function GET() {
  try {
    const res = await fetch(`${SCANNER_URL}/api/v1/health`, { cache: "no-store" });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { status: "offline", error: "Scanner service unavailable" },
      { status: 503 },
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const form = await request.formData();
    const res = await fetch(`${SCANNER_URL}/api/v1/scan`, {
      method: "POST",
      body: form,
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Scanner unavailable" },
      { status: 503 },
    );
  }
}
