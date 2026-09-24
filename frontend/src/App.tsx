import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiClient, ApiClientError } from "./api/client";
import { SimulationApi } from "./api/simulations";
import type { Page, SimulationRun, SimulationStatus } from "./api/types";
import { AuthProvider } from "./auth/AuthProvider";
import { useAuth } from "./auth/useAuth";
import { AppShell, type AppView } from "./components/AppShell";
import { ErrorState } from "./components/States";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { NewSimulationPage } from "./pages/NewSimulationPage";
import { SecurityPage } from "./pages/SecurityPage";
import { SimulationDetailPage } from "./pages/SimulationDetailPage";
import { SimulationListPage } from "./pages/SimulationListPage";

interface Route { readonly view: AppView; readonly runId?: string; }
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export default function App() {
  return <AuthProvider><ProtectedApplication /></AuthProvider>;
}

function ProtectedApplication() {
  const auth = useAuth();
  if (!auth.authenticated || !auth.identity) return <LoginPage />;
  return <CommandCenter />;
}

function CommandCenter() {
  const auth = useAuth();
  const identity = auth.identity;
  if (!identity) throw new Error("Authenticated application requires an identity");
  const [lastRequestId, setLastRequestId] = useState<string | null>(null);
  const [apiStatus, setApiStatus] = useState<"checking" | "online" | "offline">("checking");
  const [route, setRoute] = useState<Route>(readRoute);
  const [page, setPage] = useState<Page<SimulationRun> | null>(null);
  const [status, setStatus] = useState<SimulationStatus | "">("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const api = useMemo(() => new SimulationApi(new ApiClient(apiBaseUrl, () => auth.token, setLastRequestId, auth.expire)), [auth.token, auth.expire]);
  const navigate = useCallback((view: Exclude<AppView, "detail">) => { window.location.hash = view === "dashboard" ? "/" : `/${view}`; }, []);
  const openRun = useCallback((runId: string) => { window.location.hash = `/simulations/${runId}`; }, []);
  const loadRuns = useCallback(async (offset = 0, nextStatus = status) => { setLoading(true); try { setPage(await api.list(20, offset, nextStatus || undefined)); setError(null); } catch (reason: unknown) { setError(reason); } finally { setLoading(false); } }, [api, status]);
  useEffect(() => { const updateRoute = () => setRoute(readRoute()); window.addEventListener("hashchange", updateRoute); return () => window.removeEventListener("hashchange", updateRoute); }, []);
  useEffect(() => { void fetch(`${apiBaseUrl}/health`).then((response) => setApiStatus(response.ok ? "online" : "offline")).catch(() => setApiStatus("offline")); }, []);
  useEffect(() => { if (route.view === "dashboard" || route.view === "simulations") void Promise.resolve().then(() => loadRuns(route.view === "simulations" ? page?.offset ?? 0 : 0)); }, [route.view, loadRuns, page?.offset]);
  const canCreate = auth.hasPermission("simulation:create");
  const canApprove = auth.hasPermission("simulation:approve") && auth.hasPermission("simulation:reject");
  const canCancel = auth.hasPermission("simulation:cancel");
  const canReadAudit = auth.hasPermission("audit:read");
  const canAdmin = auth.hasPermission("security:admin");
  const selectStatus = (nextStatus: SimulationStatus | "") => { setStatus(nextStatus); void loadRuns(0, nextStatus); };
  let content: React.ReactNode;
  if (route.view === "dashboard") content = <DashboardPage page={page} loading={loading} error={error} onSelect={openRun} onViewAll={() => navigate("simulations")} onCreate={() => navigate("new-simulation")} canCreate={canCreate} />;
  else if (route.view === "simulations") content = <SimulationListPage page={page} status={status} loading={loading} error={error} onStatus={selectStatus} onRefresh={() => void loadRuns(page?.offset ?? 0)} onSelect={openRun} onPageChange={(offset) => void loadRuns(offset)} onCreate={() => navigate("new-simulation")} canCreate={canCreate} />;
  else if (route.view === "new-simulation") content = canCreate ? <NewSimulationPage api={api} canCreate onCreated={openRun} /> : <ErrorState error={new ApiClientError("Forbidden", 403, "FORBIDDEN", lastRequestId)} />;
  else if (route.view === "security") content = canAdmin ? <SecurityPage api={api} /> : <ErrorState error={new ApiClientError("Forbidden", 403, "FORBIDDEN", lastRequestId)} />;
  else content = <SimulationDetailPage api={api} runId={route.runId ?? ""} canApprove={canApprove} canCancel={canCancel} canReadAudit={canReadAudit} onBack={() => navigate("simulations")} />;
  return <AppShell view={route.view} apiStatus={apiStatus} lastRequestId={lastRequestId} onNavigate={navigate} identity={identity} onLogout={() => void auth.logout()}>{content}</AppShell>;
}

function readRoute(): Route {
  const path = window.location.hash.replace(/^#/, "") || "/";
  const detail = path.match(/^\/simulations\/([0-9a-f-]{36})$/i);
  if (detail) return { view: "detail", runId: detail[1] };
  if (path === "/simulations") return { view: "simulations" };
  if (path === "/new-simulation") return { view: "new-simulation" };
  if (path === "/security") return { view: "security" };
  return { view: "dashboard" };
}
