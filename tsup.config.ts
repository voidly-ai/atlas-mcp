import { defineConfig } from 'tsup';

export default defineConfig({
  // cli.ts is the owner command line; index.ts loads it only for `voidly-mcp relay ...`.
  entry: ['src/index.ts', 'src/cli.ts'],
  format: ['esm'],
  platform: 'node',
  target: 'es2022',
  clean: true,
  minify: true,
  treeshake: true,
  dts: { entry: 'src/index.ts' },
  banner: {
    js: '#!/usr/bin/env node',
  },
});
