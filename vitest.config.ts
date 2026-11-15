import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // tests/attack 是独立 CLI（npm run attack），自带服务生命周期，不进 vitest
    exclude: ['node_modules', 'tests/attack/**', 'tests/helpers/**'],
  },
});
