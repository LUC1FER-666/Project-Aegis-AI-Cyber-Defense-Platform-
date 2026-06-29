/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: "/api/gateway/:path*",
        destination: "http://localhost:8000/api/v1/:path*",
      },
      {
        source: "/api/assets/:path*",
        destination: "http://localhost:8001/api/v1/:path*",
      },
      {
        source: "/api/telemetry/:path*",
        destination: "http://localhost:8002/api/v1/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
