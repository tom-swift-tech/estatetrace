let sessionToken = "";

export async function ensureSession() {
  if (sessionToken) return sessionToken;
  const res = await fetch("/api/session");
  const data = await res.json();
  sessionToken = data.token;
  return sessionToken;
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  await ensureSession();
  const headers = new Headers(init.headers);
  headers.set("x-session-token", sessionToken);
  if (init.body && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const res = await fetch(`/api${path}`, { ...init, headers });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.json();
}