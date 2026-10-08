/** Authentication boundary for the frontend (spec §26). */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { AuthSessionSchema, UserSchema, type User } from '@aegis/contracts';
import { apiRequest, getToken, setToken } from '../lib/api.js';

interface AuthContextValue {
  user: User | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, name: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }): ReactNode {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const bootstrap = async () => {
      if (!getToken()) {
        setReady(true);
        return;
      }
      try {
        const me = await apiRequest('GET', '/api/auth/me', UserSchema);
        if (!cancelled) setUser(me);
      } catch {
        setToken(null);
      } finally {
        if (!cancelled) setReady(true);
      }
    };
    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const session = await apiRequest(
      'POST',
      '/api/auth/login',
      AuthSessionSchema,
      { email, password },
    );
    setToken(session.token);
    setUser(session.user);
  }, []);

  const register = useCallback(async (email: string, name: string, password: string) => {
    await apiRequest('POST', '/api/auth/register', UserSchema, { email, name, password });
    await login(email, password);
  }, [login]);

  const logout = useCallback(async () => {
    try {
      await apiRequest('POST', '/api/auth/logout', UserSchema);
    } catch {
      // Token may already be invalid; clear locally regardless.
    }
    setToken(null);
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, ready, login, register, logout }),
    [user, ready, login, register, logout],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
