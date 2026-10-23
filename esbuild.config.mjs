import esbuild from "esbuild";

const production = process.argv.includes("--production");

await esbuild.build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  // "browser" makes the build fail on any Node built-in import, which would
  // break the plugin on Obsidian mobile.
  platform: "browser",
  format: "cjs",
  target: "es2022",
  external: ["obsidian", "electron"],
  sourcemap: production ? false : "inline",
  minify: production,
  treeShaking: true,
  logLevel: "info",
  outfile: "main.js",
});
