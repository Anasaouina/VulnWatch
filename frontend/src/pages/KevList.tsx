import { useEffect } from "react";
import CveTable from "../components/CveTable";

export default function KevList() {
  useEffect(() => {
    document.title = "Known Exploited — VulnWatch";
  }, []);
  return (
    <div>
      <CveTable
        kevOnlyDefault
        showKevDateColumn
        baseTitle="Known Exploited"
        description="CVEs from the CISA Known Exploited Vulnerabilities catalog. These are observed in exploitation — treat watchlist matches here as urgent, but verify your exposure."
      />
    </div>
  );
}
