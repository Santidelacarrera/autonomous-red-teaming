import { useCallback, useMemo, useState } from "react";
import { ApiClient, ApiClientError } from "../api/client";
import type { ApiRole, Identity } from "../api/types";
import { AuthContext, type AuthContextValue } from "./context";
import type { BrowserOidcAdapter } from "./oidc";

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export function AuthProvider({ children, oidcAdapter }: { readonly children: React.ReactNode; readonly oidcAdapter?: BrowserOidcAdapter }) {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const developmentMode = (import.meta.env.VITE_AUTH_MODE ?? (import.meta.env.DEV ? "development" : "oidc")) === "development";

  const loginDevelopment = useCallback(async (role: ApiRole, subject: string): Promise<void> => {
    if (!developmentMode) { setError("Development authentication is unavailable in this environment."); return; }
    if (!subject.trim()) { setError("A development subject is required."); return; }
    const candidate = `development:${role}:${subject.trim()}`;
    setLoading(true);
    setError(null);
    try {
      const verified = await new ApiClient(apiBaseUrl, () => candidate).request<Identity>("/api/v1/identity");
      setToken(candidate);
      setIdentity(verified);
    } catch (reason: unknown) {
      setToken(null);
      setIdentity(null);
      setError(reason instanceof ApiClientError ? reason.message : "Authentication could not be completed.");
    } finally {
      setLoading(false);
    }
  }, [developmentMode]);

  const loginOidc = useCallback(async (): Promise<void> => {
    if (!oidcAdapter) { setError("The deployment has not configured its OIDC PKCE adapter."); return; }
    setLoading(true);
    setError(null);
    try {
      const candidate = await oidcAdapter.authorizeWithPkce();
      const verified = await new ApiClient(apiBaseUrl, () => candidate).request<Identity>("/api/v1/identity");
      setToken(candidate);
      setIdentity(verified);
    } catch (reason: unknown) {
      setToken(null);
      setIdentity(null);
      setError(reason instanceof ApiClientError ? reason.message : "OIDC authentication could not be completed.");
    } finally {
      setLoading(false);
    }
  }, [oidcAdapter]);

  const expire = useCallback(() => { setToken(null); setIdentity(null); setError("Your authentication is missing or has expired."); }, []);
  const logout = useCallback(async (): Promise<void> => {
    const current = token;
    setLoading(true);
    try {
      if (current) await new ApiClient(apiBaseUrl, () => current).request<void>("/api/v1/logout", { method: "POST" });
      if (identity?.authentication.method === "oidc" && oidcAdapter) await oidcAdapter.endSession(identity);
    } finally {
      setToken(null);
      setIdentity(null);
      setError(null);
      setLoading(false);
      window.location.hash = "/";
    }
  }, [identity, oidcAdapter, token]);
  const hasPermission = useCallback((permission: string) => identity?.permissions.includes(permission) ?? false, [identity]);
  const value = useMemo<AuthContextValue>(() => ({ authenticated: identity !== null && token !== null, identity, token, loading, error, developmentMode, oidcProviderName: oidcAdapter?.providerName ?? null, loginDevelopment, loginOidc, logout, expire, hasPermission }), [identity, token, loading, error, developmentMode, oidcAdapter?.providerName, loginDevelopment, loginOidc, logout, expire, hasPermission]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
