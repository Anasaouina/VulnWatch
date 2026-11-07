import CveTable from "../components/CveTable";

export default function CveList() {
  return (
    <CveTable
      baseTitle="Latest CVEs"
      description="Newly collected vulnerabilities, newest first. Search by CVE ID or keyword and filter by severity, publication date, watchlist match or exploitation status."
    />
  );
}
