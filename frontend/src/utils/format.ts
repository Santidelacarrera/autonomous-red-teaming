export function formatTimestamp(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function shortId(value: string): string { return value.slice(0, 8); }

export function formatRisk(value: number | null): string { return value === null ? "N/A" : value.toFixed(1); }
