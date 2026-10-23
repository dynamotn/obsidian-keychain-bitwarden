// HTTPS front for the test Vaultwarden: the official Bitwarden CLI refuses
// plain http. Uses a throwaway self-signed certificate valid for one day.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:https";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

export interface TlsProxy {
  url: string;
  caFile: string;
  close(): Promise<void>;
}

export async function startTlsProxy(target: string): Promise<TlsProxy> {
  const dir = mkdtempSync(join(tmpdir(), "bw-it-tls-"));
  const key = join(dir, "key.pem");
  const cert = join(dir, "cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
  ], { stdio: "ignore" });

  const upstream = new URL(target);
  const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
    const out = httpRequest(
      {
        host: upstream.hostname,
        port: upstream.port,
        method: req.method,
        path: req.url,
        headers: { ...req.headers, host: upstream.host },
      },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers);
        up.pipe(res);
      },
    );
    out.on("error", () => res.writeHead(502).end());
    req.pipe(out);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `https://127.0.0.1:${port}`,
    caFile: cert,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
