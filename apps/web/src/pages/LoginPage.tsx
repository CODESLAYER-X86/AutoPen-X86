import { useState, type FormEvent, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext.js';
import { ApiError } from '../lib/api.js';
import { ErrorBanner } from '../components/Feedback.js';

export function LoginPage(): ReactNode {
  const { login, register, user } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) {
    navigate('/', { replace: true });
  }

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'login') {
        await login(email, password);
      } else {
        await register(email, name, password);
      }
      navigate('/', { replace: true });
    } catch (err) {
      const message =
        err instanceof ApiError ? err.message : 'Unexpected error during authentication';
      setError(message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-box">
        <h1>AEGIS</h1>
        <p className="tagline">Autonomous web security testing &amp; CTF platform</p>
        <form className="form" onSubmit={onSubmit}>
          {mode === 'register' && (
            <label className="field">
              Name
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                minLength={1}
                maxLength={200}
                autoComplete="name"
              />
            </label>
          )}
          <label className="field">
            Email
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              maxLength={320}
              autoComplete="email"
            />
          </label>
          <label className="field">
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={mode === 'register' ? 10 : 1}
              maxLength={128}
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </label>
          <ErrorBanner message={error} />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Working…' : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>
        <div className="mode-switch">
          {mode === 'login' ? (
            <span>
              No account?{' '}
              <button type="button" onClick={() => setMode('register')}>
                Create one
              </button>
            </span>
          ) : (
            <span>
              Already registered?{' '}
              <button type="button" onClick={() => setMode('login')}>
                Sign in
              </button>
            </span>
          )}
        </div>
        <p className="auth-warning">
          Authorized security testing only. Every engagement requires an explicit scope; all
          activity is logged and auditable.
        </p>
      </div>
    </div>
  );
}
