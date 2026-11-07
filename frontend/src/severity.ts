import type { SeverityBucket } from "./api";

export const severityLabel: Record<SeverityBucket, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
};

export function severityDisplay(item: {
  severity_bucket: SeverityBucket;
  cvss_score: number | null;
  stated_severity: string | null;
}): string {
  if (item.cvss_score != null) {
    return `${severityLabel[item.severity_bucket]} (${item.cvss_score})`;
  }
  if (item.stated_severity) {
    return `${severityLabel[item.severity_bucket]} (stated)`;
  }
  return "Unknown";
}
