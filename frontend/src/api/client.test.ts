import { ApiError, configureClient, listAlerts, login, updateStatus } from "./client";

function respond(status: number, body: unknown) {
  return vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }));
}

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("sends the bearer token and only the filters that are set", async () => {
    configureClient({ getToken: () => "tok", onUnauthorized: () => {} });
    const fetchMock = respond(200, { items: [], total: 0, limit: 10, offset: 0 });
    vi.stubGlobal("fetch", fetchMock);

    await listAlerts({ status: "open", severity: undefined, limit: 10 });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/alerts?status=open&limit=10");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer tok");
  });

  it("logs in with a form-encoded body (OAuth2 password flow)", async () => {
    const fetchMock = respond(200, { access_token: "abc" });
    vi.stubGlobal("fetch", fetchMock);

    await expect(login("a@b.co", "pw")).resolves.toBe("abc");

    const init = fetchMock.mock.calls[0]![1] as RequestInit;
    expect((init.body as URLSearchParams).get("username")).toBe("a@b.co");
  });

  it("turns API errors into ApiError with the server's message", async () => {
    configureClient({ getToken: () => "tok", onUnauthorized: () => {} });
    vi.stubGlobal("fetch", respond(403, { detail: "Insufficient role" }));

    await expect(updateStatus(1, "resolved")).rejects.toMatchObject({ status: 403, message: "Insufficient role" });
  });

  it("signs the user out on 401 for authenticated calls, but not for a failed login", async () => {
    const onUnauthorized = vi.fn();
    configureClient({ getToken: () => "tok", onUnauthorized });

    vi.stubGlobal("fetch", respond(401, { detail: "Invalid credentials" }));
    await expect(login("a@b.co", "bad")).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).not.toHaveBeenCalled();

    vi.stubGlobal("fetch", respond(401, { detail: "expired" }));
    await expect(listAlerts()).rejects.toBeInstanceOf(ApiError);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("reports a network failure in plain language", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(listAlerts()).rejects.toMatchObject({ status: 0 });
  });
});
