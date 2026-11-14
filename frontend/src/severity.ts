import type { Priority, SeverityBucket } from "./api";

export const severityLabel: Record<SeverityBucket, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
};

/** VulnWatch priority labels — our assessment, not an official rating. */
export const priorityLabel: Record<Priority, string> = {
  urgent: "P-Urgent",
  high: "P-High",
  medium: "P-Medium",
  low: "P-Low",
  unknown: "P-Unknown",
};

export const PRIORITY_DOC =
  "VulnWatch priority: our assessment combining CVSS severity, FIRST EPSS exploitation likelihood and CISA KEV listing; not an official FIRST, CISA or CVSS rating.";

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
