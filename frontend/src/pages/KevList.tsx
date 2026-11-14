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
        description="CVEs listed in the CISA Known Exploited Vulnerabilities catalog — confirmed exploited in the wild per CISA. VulnWatch priority marks every listing URGENT by rule, but a listed CVE is not proof that a system you run is affected; verify exposure. The catalog is also not an exhaustive list of all exploited vulnerabilities."
      />
    </div>
  );
}
