import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import icon from "astro-icon";

export default defineConfig({
  site: "https://withrelay.dev",
  server: { host: "127.0.0.1" },
  integrations: [icon({ include: { lucide: ["*"] } })],
  vite: {
    plugins: [tailwindcss()],
    server: {
      allowedHosts: ["relay-dev.sharedwithrelay.com", ".sharedwithrelay.com"],
      hmr: {
        host: "relay-dev.sharedwithrelay.com",
        protocol: "wss",
        clientPort: 443,
      },
    },
  },
});
