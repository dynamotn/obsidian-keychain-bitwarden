// Transport abstraction: the plugin plugs in Obsidian's requestUrl (which is
// not subject to CORS on mobile), tests plug in fetch.

export interface HttpRequest {
  url: string;
  method: "GET" | "POST" | "PUT" | "DELETE";
  headers?: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  text: string;
}

export type HttpClient = (req: HttpRequest) => Promise<HttpResponse>;

export const fetchHttpClient: HttpClient = async (req) => {
  const res = await fetch(req.url, { method: req.method, headers: req.headers, body: req.body });
  return { status: res.status, text: await res.text() };
};
