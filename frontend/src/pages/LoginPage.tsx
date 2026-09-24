import { useState } from "react";
import type { ApiRole } from "../api/types";
import { useAuth } from "../auth/useAuth";

export function LoginPage() {
  const auth = useAuth();
  const [role, setRole] = useState<ApiRole>("operator");
  const [subject, setSubject] = useState("local-operator");
  return <main className="login-shell"><section className="login-panel"><div className="brand login-brand"><span className="brand-mark">A</span><span><b>AUTONOMOUS</b><small>RED TEAMING</small></span></div><span className="eyebrow">IDENTITY BOUNDARY</span><h1>Command Center access</h1>{auth.developmentMode ? <><p>Local development authentication. This identity format is rejected outside the development profile.</p><label>Role<select value={role} onChange={(event) => setRole(event.target.value as ApiRole)}><option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option></select></label><label>Subject<input value={subject} maxLength={128} onChange={(event) => setSubject(event.target.value)} /></label>{auth.error ? <p className="login-error" role="alert">{auth.error}</p> : null}<button className="primary-button" disabled={auth.loading} onClick={() => void auth.loginDevelopment(role, subject)}>{auth.loading ? "Authenticating…" : "Sign in to development"}</button></> : <><p>Production access uses the deployment OIDC provider with Authorization Code and PKCE.</p>{auth.error ? <p className="login-error" role="alert">{auth.error}</p> : null}<button className="primary-button" disabled={auth.loading || !auth.oidcProviderName} onClick={() => void auth.loginOidc()}>{auth.oidcProviderName ? `Continue with ${auth.oidcProviderName}` : "OIDC adapter not configured"}</button></>}</section></main>;
}
