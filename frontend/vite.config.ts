import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Strict Content-Security-Policy injected only into the production build so the
// Vite dev server (inline HMR preamble + websocket) keeps working locally.
// Deployments SHOULD prefer serving this as an HTTP response header; the meta tag
// is a defense-in-depth fallback for static hosting. `connect-src 'self'` assumes
// the API is same-origin (reverse-proxied under /api); adjust it if the API is
// served from a different origin.
const PRODUCTION_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join("; ");

function cspPlugin(): Plugin {
  return {
    name: "inject-production-csp",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        "</title>",
        `</title><meta http-equiv="Content-Security-Policy" content="${PRODUCTION_CSP}" />`,
      );
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react(), cspPlugin()],
    server: {
      proxy: {
        "/api": { target: env.VITE_BACKEND_URL || "http://127.0.0.1:8080", changeOrigin: false },
        "/health": { target: env.VITE_BACKEND_URL || "http://127.0.0.1:8080", changeOrigin: false },
      },
    },
    test: { environment: "jsdom", setupFiles: ["./src/test/setup.ts"] },
  };
});
