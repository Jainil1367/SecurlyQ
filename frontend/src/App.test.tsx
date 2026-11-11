import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import type { Alert, AlertDetail } from "./api/types";
import { fakeBackend, renderApp } from "./test/render";

const alert: Alert = {
  id: 7, rule_id: "failure_then_success", title: "Successful login after 24 failed attempts", severity: "critical",
  risk_score: 98.7, anomaly_score: 1, status: "open", source_ip: "198.18.5.31", username: null,
  created_at: "2026-11-11T11:00:00Z", acknowledged_at: null, evidence_count: 25,
};
const detail: AlertDetail = {
  ...alert, explanation: null, investigation_notes: [],
  evidence: [{ reason: "5th failure in window", event: { id: 1, source: "auth", event_type: "login", outcome: "failure", timestamp: "2026-11-11T10:59:00Z", source_ip: "198.18.5.31", username: "alice", attributes: {} } }],
};
const summary = { total_alerts: 1, by_status: { open: 1 }, open_by_severity: { critical: 1 }, top_source_ips: [{ source_ip: "198.18.5.31", alerts: 1 }], mean_time_to_acknowledge_seconds: null };
const analyst = { id: 1, email: "ana@example.com", role: "analyst", created_at: "2026-11-01T00:00:00Z" };

beforeEach(() => sessionStorage.clear());
afterEach(() => vi.unstubAllGlobals());

describe("auth gate", () => {
  it("redirects an anonymous visitor to the sign-in form", async () => {
    fakeBackend({});
    renderApp(<App />, "/alerts");
    expect(await screen.findByRole("heading", { name: /sign in to securlyq/i })).toBeInTheDocument();
  });

  it("shows the server's message when credentials are wrong", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Incorrect email or password" }), { status: 401 })));
    renderApp(<App />, "/login");
    await userEvent.type(screen.getByLabelText(/email/i), "ana@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "nope");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect email or password");
  });
});

describe("alerts dashboard", () => {
  beforeEach(() => sessionStorage.setItem("securlyq.token", "tok"));

  it("shows KPIs and the queue, with severity as text (not color alone)", async () => {
    fakeBackend({
      "GET /api/v1/auth/me": analyst,
      "GET /api/v1/alerts/summary": summary,
      "GET /api/v1/alerts": { items: [alert], total: 1, limit: 10, offset: 0 },
    });
    renderApp(<App />, "/alerts");

    const queue = await screen.findByRole("region", { name: /alert queue/i });
    expect(await within(queue).findByText("Successful login after 24 failed attempts")).toBeInTheDocument();
    expect(within(within(queue).getByRole("link")).getByText("Critical")).toBeInTheDocument();
    expect(await screen.findByText("Acknowledge an alert to start tracking")).toBeInTheDocument(); // MTTA empty state
  });

  it("shows an empty state instead of a blank table", async () => {
    fakeBackend({
      "GET /api/v1/auth/me": analyst,
      "GET /api/v1/alerts/summary": { ...summary, total_alerts: 0, by_status: {}, open_by_severity: {}, top_source_ips: [] },
      "GET /api/v1/alerts": { items: [], total: 0, limit: 10, offset: 0 },
    });
    renderApp(<App />, "/alerts");
    expect(await screen.findByText(/no alerts match these filters/i)).toBeInTheDocument();
  });

  it("hides write actions from viewers", async () => {
    fakeBackend({
      "GET /api/v1/auth/me": { ...analyst, role: "viewer" },
      "GET /api/v1/alerts/summary": summary,
      "GET /api/v1/alerts": { items: [alert], total: 1, limit: 10, offset: 0 },
    });
    renderApp(<App />, "/alerts");
    await screen.findByText("Successful login after 24 failed attempts");
    expect(screen.queryByRole("button", { name: /run analysis/i })).not.toBeInTheDocument();
  });
});

describe("alert detail", () => {
  beforeEach(() => sessionStorage.setItem("securlyq.token", "tok"));

  it("acknowledges an alert through the API", async () => {
    const fetchMock = fakeBackend({
      "GET /api/v1/auth/me": analyst,
      "GET /api/v1/alerts/7": detail,
      "PATCH /api/v1/alerts/7": { ...alert, status: "acknowledged" },
    });
    renderApp(<App />, "/alerts/7");

    await userEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));

    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(([, init]) => init?.method === "PATCH");
      expect(patch).toBeDefined();
      expect(JSON.parse(String(patch![1]!.body))).toEqual({ status: "acknowledged" });
    });
  });

  it("renders the evidence timeline and a generate button when there is no explanation yet", async () => {
    fakeBackend({ "GET /api/v1/auth/me": analyst, "GET /api/v1/alerts/7": detail });
    renderApp(<App />, "/alerts/7");
    expect(await screen.findByText("5th failure in window")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /explain this alert/i })).toBeInTheDocument();
  });
});
