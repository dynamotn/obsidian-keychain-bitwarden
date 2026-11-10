// Frozen test-only copy of src/bw/http.ts at 49a52fc (M6 Task 8): the tests' crypto oracle once src/bw is gone.
// Transport abstraction: the plugin plugs in Obsidian's requestUrl (which is
// not subject to CORS on mobile), tests plug in fetch (test/helpers/fetchHttp.ts).

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
