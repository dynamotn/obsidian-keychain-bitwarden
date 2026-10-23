// The rules Obsidian's community plugin review runs, applied to the plugin
// source. Tests and build scripts run under Node and are not part of the
// shipped plugin, so they are left out.
import { defineConfig, globalIgnores } from "eslint/config";
import obsidianmd from "eslint-plugin-obsidianmd";

export default defineConfig([
  globalIgnores([".worktrees/", "main.js", "node_modules/", "coverage/", "test/", "scripts/", "*.config.*"]),
  ...obsidianmd.configs.recommended,
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "obsidianmd/ui/sentence-case": ["error", { brands: ["Bitwarden", "Obsidian"], acronyms: ["API", "URL", "ID", "US", "EU"] }],
    },
  },
]);
