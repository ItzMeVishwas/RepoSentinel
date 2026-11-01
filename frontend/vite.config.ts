import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The production build goes into the Python package, which serves it with a
// strict Content-Security-Policy (scripts and styles only from its own origin).
export default defineConfig({
  plugins: [react()],
  // Relative URLs: the app is served under a per-launch secret path (/s/<prefix>/),
  // and its assets and API calls must stay under it.
  base: './',
  build: {
    outDir: '../src/reposentinel/webui/static',
    emptyOutDir: true,
    sourcemap: false,
    // No inline scripts: the module preload polyfill would be inlined.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
