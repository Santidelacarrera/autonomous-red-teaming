import type { ReactNode } from "react";

export function Panel({ title, eyebrow, children, className = "" }: { readonly title?: string; readonly eyebrow?: string; readonly children: ReactNode; readonly className?: string }) {
  return <section className={`panel ${className}`}>{title ? <header className="panel-heading">{eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}<h2>{title}</h2></header> : null}{children}</section>;
}

export function MetricCard({ label, value, detail, accent = "cyan" }: { readonly label: string; readonly value: string | number; readonly detail: string; readonly accent?: "cyan" | "violet" | "amber" | "green" }) {
  return <section className={`metric-card ${accent}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></section>;
}
