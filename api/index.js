import { requestHandler } from "../server/app.js";

export default function handler(request, response) {
  const incoming = new URL(request.url, `https://${request.headers.host || "localhost"}`);
  const routedPath = incoming.searchParams.get("_chrollo_path");
  if (routedPath !== null) {
    incoming.searchParams.delete("_chrollo_path");
    const query = incoming.searchParams.toString();
    request.url = `/api/${routedPath}${query ? `?${query}` : ""}`;
  }
  return requestHandler(request, response);
}
