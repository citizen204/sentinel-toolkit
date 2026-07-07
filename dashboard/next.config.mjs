import path from "path";

/** @type {import('next').NextConfig} */
const nextConfig = {
  devIndicators: false,
  // Pin the workspace root so Next doesn't infer it from a parent lockfile.
  outputFileTracingRoot: path.join(import.meta.dirname, "."),
};

export default nextConfig;
