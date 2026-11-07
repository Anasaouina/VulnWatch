import { Navigate, Route, Routes } from "react-router-dom";
import Shell from "./components/Layout";
import { SyncProvider } from "./sync-context";
import Overview from "./pages/Overview";
import CveList from "./pages/CveList";
import KevList from "./pages/KevList";
import CveDetail from "./pages/CveDetail";
import Watchlist from "./pages/Watchlist";
import FeedStatus from "./pages/FeedStatus";

export default function App() {
  return (
    <SyncProvider>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Overview />} />
          <Route path="cves" element={<CveList />} />
          <Route path="cves/:id" element={<CveDetail />} />
          <Route path="watchlist" element={<Watchlist />} />
          <Route path="kev" element={<KevList />} />
          <Route path="feeds" element={<FeedStatus />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </SyncProvider>
  );
}
