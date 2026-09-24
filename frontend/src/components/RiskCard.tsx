export function RiskCard({ before, after }: { before: number | null; after: number | null }) {
  return <section className="card" aria-labelledby="risk-heading"><h3 id="risk-heading">Risk</h3><strong>{before ?? "Not available"}</strong><span> Before simulation</span>{after !== null && <p>After: {after}</p>}</section>;
}
