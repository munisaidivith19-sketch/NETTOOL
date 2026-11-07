import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    // In dev the browser only ever talks to Vite; Vite forwards API calls to FastAPI,
    // so the app behaves as same-origin exactly like production (no CORS needed).
    proxy: {
      "/api": backend,
      "/health": backend,
    },
  },
  build: {
    sourcemap: false,
    // Never inline small files as data: URIs. The CSP allows fonts and scripts from 'self'
    // only, so an inlined font subset was blocked (found by the Phase 4 browser check).
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/__tests__/setup.js"],
  },
});
