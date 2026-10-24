// Runs in Node before the browser suites: builds the worker exactly as the
// plugin embeds it and hands its source to the tests.
import type { TestProject } from "vitest/node";
import { buildArgon2Worker } from "../../scripts/argon2-worker.mjs";

declare module "vitest" {
  export interface ProvidedContext {
    argon2WorkerSource: string;
  }
}

export default async function setup(project: TestProject): Promise<void> {
  project.provide("argon2WorkerSource", await buildArgon2Worker());
}
