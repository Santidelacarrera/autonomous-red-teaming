import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react()],
    server: {
      proxy: {
        "/api": { target: env.VITE_BACKEND_URL || "http://127.0.0.1:8080", changeOrigin: false },
        "/health": { target: env.VITE_BACKEND_URL || "http://127.0.0.1:8080", changeOrigin: false },
      },
    },
    test: { environment: "jsdom", setupFiles: ["./src/test/setup.ts"] },
  };
});
