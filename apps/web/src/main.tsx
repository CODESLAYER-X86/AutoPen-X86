import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { RouterProvider } from 'react-router-dom';
import { AppRouter } from './App.js';
import './styles.css';

const container = document.getElementById('root');
if (!container) throw new Error('root element missing');

createRoot(container).render(
  <StrictMode>
    <RouterProvider router={AppRouter} />
  </StrictMode>,
);
