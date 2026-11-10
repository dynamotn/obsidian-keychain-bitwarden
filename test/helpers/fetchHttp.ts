import type { HttpClient } from "./bw/http";

/** Real network transport for the integration tests, refusing redirects; the plugin uses requestUrl, which follows them. */
export const fetchHttpClient: HttpClient = async (req) => {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body, redirect: "error" });
  return { status: res.status, text: await res.text() };
};
