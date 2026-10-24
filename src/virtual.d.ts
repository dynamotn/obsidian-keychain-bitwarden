/** Source of the bundled Argon2 worker, embedded at build time by esbuild.config.mjs. */
declare module "virtual:argon2-worker" {
  const source: string;
  export default source;
}
