// Entry point of the Argon2 worker. esbuild bundles it on its own and embeds
// the result in main.js as text (see esbuild.config.mjs), because a plugin
// ships as a single file.

import { argon2id } from "hash-wasm";
import type { WorkerRequest, WorkerResponse } from "./argon2";

const scope = self as unknown as {
  onmessage: ((ev: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse, transfer: Transferable[]): void;
};

scope.onmessage = (ev) => {
  const req = ev.data;
  const password = new Uint8Array(req.password);
  argon2id({
    password,
    salt: new Uint8Array(req.salt),
    iterations: req.iterations,
    memorySize: req.memoryKiB,
    parallelism: req.parallelism,
    hashLength: 32,
    outputType: "binary",
  }).then(
    (out) => {
      password.fill(0);
      const key = new Uint8Array(out).buffer;
      out.fill(0);
      scope.postMessage({ key }, [key]);
    },
    (e: unknown) => {
      password.fill(0);
      scope.postMessage({ error: e instanceof Error ? e.message : String(e) }, []);
    },
  );
};
