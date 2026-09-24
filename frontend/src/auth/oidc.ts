import type { Identity } from "../api/types";

export interface BrowserOidcAdapter {
  readonly providerName: string;
  authorizeWithPkce(): Promise<string>;
  endSession(identity: Identity): Promise<void>;
}
