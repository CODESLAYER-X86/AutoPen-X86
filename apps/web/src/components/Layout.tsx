import type { ReactNode } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext.js';

export function Layout(): ReactNode {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <nav className="sidebar">
        <div className="sidebar-brand">
          AEGIS
          <small>security testing platform</small>
        </div>
        <NavLink to="/" end className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
          Dashboard
        </NavLink>
        <NavLink to="/projects" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
          Projects
        </NavLink>
        <NavLink to="/settings" className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>
          Settings
        </NavLink>
        <div className="sidebar-footer">
          <div className="user-chip">{user ? `${user.name} · ${user.email}` : 'not signed in'}</div>
          <button type="button" className="btn btn-small" style={{ margin: '8px 12px 0' }} onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
