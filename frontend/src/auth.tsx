import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { configureClient, getMe, login as apiLogin } from "./api/client";
import type { Role, User } from "./api/types";
import { readStorage, writeStorage } from "./lib/storage";

// Tradeoff: sessionStorage keeps you signed in across reloads but clears when the tab closes.
// A token in JS-readable storage is exposed to XSS; the production hardening step (Phase 7)
// is an httpOnly cookie. See docs/lessons/phase-5-dashboard.md.
const TOKEN_KEY = "securlyq.token";

interface AuthState {
  user: User | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => void;
  can: (...roles: Role[]) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(() => readStorage("session", TOKEN_KEY));
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(() => readStorage("session", TOKEN_KEY) !== null);

  const signOut = useCallback(() => {
    writeStorage("session", TOKEN_KEY, null);
    setToken(null);
    setUser(null);
    queryClient.clear();
  }, [queryClient]);

  // Keep the API client pointed at the current token. Runs before children fetch.
  configureClient({ getToken: () => token, onUnauthorized: signOut });

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    getMe()
      .then((u) => !cancelled && setUser(u))
      .catch(() => !cancelled && signOut())
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, [token, signOut]);

  const signIn = useCallback(async (email: string, password: string) => {
    const t = await apiLogin(email, password);
    writeStorage("session", TOKEN_KEY, t);
    configureClient({ getToken: () => t, onUnauthorized: signOut });
    setLoading(true);
    setToken(t);
  }, [signOut]);

  const value = useMemo<AuthState>(
    () => ({ user, loading, signIn, signOut, can: (...roles) => !!user && roles.includes(user.role) }),
    [user, loading, signIn, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
