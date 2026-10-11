import type { InvestigationMapping } from "@/lib/investigation-api";

const SOURCE_FIELDS = {
  file: { timestamp: "timestamp", event_id: "id" },
  splunk: { timestamp: "_time", event_id: "_cd" },
} as const;

// Change only the untouched source defaults. In particular, Splunk's host
// metadata may identify the collector, so never replace the target mapping.
export function investigationMappingForSource(
  current: InvestigationMapping,
  previous: "file" | "splunk",
  next: "file" | "splunk",
): InvestigationMapping {
  const updated = { ...current };
  for (const key of ["timestamp", "event_id"] as const) {
    if (current[key] === SOURCE_FIELDS[previous][key]) updated[key] = SOURCE_FIELDS[next][key];
  }
  return updated;
}
