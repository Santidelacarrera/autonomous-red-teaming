import { createContext } from "react";
import type { ApiRole, Identity } from "../api/types";

export interface AuthContextValue {
  readonly authenticated: boolean;
  readonly identity: Identity | null;
  readonly token: string | null;
  readonly loading: boolean;
  readonly error: string | null;
  readonly developmentMode: boolean;
  readonly oidcProviderName: string | null;
  readonly loginDevelopment: (role: ApiRole, subject: string) => Promise<void>;
  readonly loginOidc: () => Promise<void>;
  readonly logout: () => Promise<void>;
  readonly expire: () => void;
  readonly hasPermission: (permission: string) => boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
