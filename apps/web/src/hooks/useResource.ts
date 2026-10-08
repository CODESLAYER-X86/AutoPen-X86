import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from '../lib/api.js';

export interface ResourceState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Minimal data-fetching hook with loading/error states (no external deps). */
export function useResource<T>(loader: () => Promise<T>, deps: unknown[]): ResourceState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    loaderRef
      .current()
      .then((result) => {
        if (!cancelled) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message =
          err instanceof ApiError ? err.message : 'Unexpected error while loading data';
        setError(message);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}
