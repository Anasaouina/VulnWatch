import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { api, type SyncStatus } from "./api";

interface SyncContextValue {
  status: SyncStatus | null;
  error: string | null;
  refresh: () => void;
}

const SyncContext = createContext<SyncContextValue>({
  status: null,
  error: null,
  refresh: () => {},
});

export function SyncProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let alive = true;
    api
      .syncStatus()
      .then((s) => {
        if (alive) {
          setStatus(s);
          setError(null);
        }
      })
      .catch((e: Error) => {
        if (alive) setError(e.message);
      });
    const id = window.setInterval(() => setTick((t) => t + 1), 30000);
    return () => {
      alive = false;
      window.clearInterval(id);
    };
  }, [tick]);

  return (
    <SyncContext.Provider value={{ status, error, refresh }}>
      {children}
    </SyncContext.Provider>
  );
}

export function useSyncStatus() {
  return useContext(SyncContext);
}
