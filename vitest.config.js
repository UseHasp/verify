import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.js"],
    testTimeout: 15000,
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary", "html", "json-summary", "lcov"],
      reportsDirectory: "coverage",
      include: ["src/**/*.js"],
      // src/cli.js is exercised by subprocess tests in test/cli.test.js, which
      // v8 in-process instrumentation cannot observe. See CONTRIBUTING.md → Test coverage.
      exclude: ["src/cli.js"],
      thresholds: {
        lines: 95,
        branches: 90,
        // vitest 4 counts function definitions slightly more strictly than v2
        // (anonymous callbacks count separately). 93 still demands 14/15 cover.
        functions: 93,
        statements: 95,
      },
    },
  },
});
