import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// The build output goes straight into the Go embed directory so the binary
// can serve the UI without any extra packaging step.
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: "../internal/server/ui/dist",
    emptyOutDir: true,
  },
  server: {
    // During development the Go API runs separately:
    //   hsmdoctor serve --listen 127.0.0.1:8080
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});
