import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // "standalone" is only needed for the self-hosted Docker image
  // (docker/Dockerfile.web copies .next/standalone). On Vercel this mode
  // can break routing, so it is opt-in via BUILD_STANDALONE=1.
  ...(process.env.BUILD_STANDALONE === "1" ? { output: "standalone" as const } : {}),
};

export default nextConfig;
