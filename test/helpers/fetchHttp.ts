import type { HttpClient } from "../../src/bw/http";

/** Real network transport for the integration tests; the plugin uses requestUrl. */
export const fetchHttpClient: HttpClient = async (req) => {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body });
  return { status: res.status, text: await res.text() };
};
