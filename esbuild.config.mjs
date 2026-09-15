import esbuild from "esbuild";

const production = process.argv[2] === "production";
await esbuild.build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  outfile: "main.js",
  format: "cjs",
  target: "es2022",
  platform: "browser",
  external: ["obsidian", "electron", "fs", "path", "crypto", "http", "https"],
  sourcemap: production ? false : "inline",
  minify: production,
  logLevel: "info"
});
