"""Turn demo evidence into a reproducible report: findings, digest, Markdown and HTML.

Two kinds of content are kept strictly apart:

* **Findings** — the graph, attack route, risk score and its justification, blast radius,
  remediation, verification and control outcomes. They are computed from deterministic inputs
  (asset IDs are ``uuid5`` of names) and serialized canonically, so *every execution on any
  machine yields the same bytes and the same SHA-256*. That digest is what a reviewer compares
  against the published one to confirm they reproduced the demonstration.
* **Run evidence** — run IDs, timestamps and the audit log of this particular execution. It is
  real and verifiable (the audit chain is checked), but differs between executions by nature,
  so it is shown separately and never enters the digest.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256
from html import escape as e
from pathlib import Path
from typing import Any

from art_sim.demo.graph_svg import render_graph_svg
from art_sim.demo.runner import DemoEvidence

DIGEST_FILE = Path(__file__).with_name("expected_findings.sha256")


def _names(ev: DemoEvidence) -> dict[Any, str]:
    return {asset.asset_id: asset.name for asset in ev.scenario.graph.assets}


def build_findings(ev: DemoEvidence) -> dict[str, Any]:
    """Assemble the deterministic findings document."""
    names = _names(ev)
    verification = ev.result.verification
    before, after = verification.blast_radius_before, verification.blast_radius_after
    remediation = ev.review.remediation
    artifact = ev.result.remediation_artifacts[0]
    return {
        "schema": "art-sim-demo-findings/1",
        "classification": "synthetic laboratory; simulation only; no real system was contacted",
        "scenario": {
            "id": ev.scenario.scenario_id,
            "graph_version": ev.scenario.graph_version,
            "assets": [
                {
                    "name": a.name,
                    "type": a.asset_type.value,
                    "criticality": a.criticality.value,
                    "crown_jewel": a.is_crown_jewel,
                }
                for a in ev.scenario.graph.assets
            ],
            "relationships": [
                [names[r.source_asset_id], r.relationship_type.value, names[r.target_asset_id]]
                for r in ev.scenario.graph.relationships
            ],
        },
        "attack_path": {
            "assets": [names[i] for i in ev.path.asset_ids],
            "relationships": [s.relationship_type.value for s in ev.path.steps],
            "hops": ev.path.hop_count,
        },
        "risk": {
            "score": ev.review.risk.score,
            "scale": "0-100",
            "reconciles": ev.explanation.reconciles,
            "factors": [
                {
                    "name": f.name,
                    "value": round(f.signed_value, 2),
                    "maximum": f.maximum,
                    "justification": f.justification,
                }
                for f in ev.explanation.factors
            ],
        },
        "blast_radius": {
            "before": {
                "reachable_assets": before.reachable_assets,
                "total_assets": before.total_assets,
                "percent": before.blast_radius_percentage,
                "crown_jewel_exposure_percent": before.crown_jewel_exposure_percentage,
            },
            "after": {
                "reachable_assets": after.reachable_assets,
                "total_assets": after.total_assets,
                "percent": after.blast_radius_percentage,
                "crown_jewel_exposure_percent": after.crown_jewel_exposure_percentage,
            },
        },
        "remediation": {
            "action": remediation.action.value,
            "severed_relation": [
                names[remediation.source_asset_id],
                remediation.relationship_type.value,
                names[remediation.target_asset_id],
            ],
            "expected_risk_reduction": remediation.expected_risk_reduction,
            "simulated_only": remediation.simulated_only,
            "artifact": {"path": artifact.file_path, "sha256": artifact.content_sha256},
        },
        "automated_preapproval": {
            "status": ev.review.automated_preapproval.status.value,
            "checks": dict(sorted(ev.review.automated_preapproval.checks.items())),
            "requires_human_approval": ev.review.automated_preapproval.requires_human_approval,
        },
        "verification": {
            "status": verification.status.value,
            "paths_removed": verification.paths_removed,
            "remaining_paths": verification.remaining_paths,
            "risk_before": verification.risk_before,
            "risk_after": verification.risk_after,
            "risk_reduction": verification.risk_reduction,
        },
        "controls": [
            {
                "control": c.control,
                "request": c.request,
                "actor": c.actor,
                "expected_status": c.expected,
                "observed_status": c.observed,
                "held": c.passed,
                "effect": c.effect,
            }
            for c in ev.controls
        ],
    }


def canonical(findings: dict[str, Any]) -> str:
    """The exact text whose SHA-256 is the published digest."""
    return json.dumps(findings, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def findings_digest(findings: dict[str, Any]) -> str:
    """SHA-256 of the canonical findings."""
    return sha256(canonical(findings).encode("utf-8")).hexdigest()


def expected_digest() -> str | None:
    """The digest committed with the source, or ``None`` when none has been recorded."""
    if not DIGEST_FILE.exists():
        return None
    return DIGEST_FILE.read_text(encoding="utf-8").split()[0]


def figures(ev: DemoEvidence) -> tuple[str, str]:
    """Render the before and after SVG figures (same layout, so they compare by eye)."""
    graph, source = ev.scenario.graph, ev.scenario.source_asset_id
    verification = ev.result.verification
    before = render_graph_svg(
        graph,
        source,
        title="Before controls",
        path=ev.path,
        summary=f"risk {verification.risk_before:.2f}/100",
        layout_from=graph,
    )
    after = render_graph_svg(
        graph.without_relationship(ev.removed_edge),
        source,
        title="After approved control",
        removed=ev.removed_edge,
        summary=f"risk {verification.risk_after:.2f}/100",
        layout_from=graph,
    )
    return before, after


# ----------------------------------------------------------------------------- Markdown


def render_markdown(ev: DemoEvidence, findings: dict[str, Any], digest: str) -> str:
    """Deterministic Markdown report (no timestamps, no run identifiers)."""
    risk, br, rem = findings["risk"], findings["blast_radius"], findings["remediation"]
    ver = findings["verification"]
    lines = [
        "# Lab demonstration report",
        "",
        "> Synthetic estate. Simulation only: no real system was scanned, contacted or changed.",
        "",
        "## Summary",
        "",
        "| Metric | Before | After |",
        "|---|---:|---:|",
        f"| Risk score (0-100) | {ver['risk_before']:.2f} | {ver['risk_after']:.2f} |",
        (
            f"| Blast radius | {br['before']['percent']:.2f}% "
            f"({br['before']['reachable_assets']}/{br['before']['total_assets']} assets) | "
            f"{br['after']['percent']:.2f}% ({br['after']['reachable_assets']}/{br['after']['total_assets']}) |"
        ),
        (
            f"| Crown-jewel exposure | {br['before']['crown_jewel_exposure_percent']:.2f}% | "
            f"{br['after']['crown_jewel_exposure_percent']:.2f}% |"
        ),
        "",
        (
            f"Verification: **{ver['status']}** — attack routes removed: {ver['paths_removed']}, "
            f"remaining: {ver['remaining_paths']}."
        ),
        "",
        "## Attack route found",
        "",
        "`" + "` → `".join(findings["attack_path"]["assets"]) + "`",
        "",
        "Relations: " + ", ".join(findings["attack_path"]["relationships"]) + ".",
        "",
        f"## Why the score is {risk['score']:.2f}",
        "",
        "| Factor | Points | Max | Evidence |",
        "|---|---:|---:|---|",
    ]
    for factor in risk["factors"]:
        maximum = "—" if factor["maximum"] == 0 else f"{factor['maximum']:.0f}"
        lines.append(
            f"| {factor['name']} | {factor['value']:+.2f} | {maximum} | {factor['justification']} |"
        )
    lines += [
        "",
        f"Factors reconcile with the reported score: **{'yes' if risk['reconciles'] else 'NO'}**.",
        "",
        "## Proposed remediation (never applied)",
        "",
        f"- Action: `{rem['action']}`",
        f"- Severs: `{rem['severed_relation'][0]}` —{rem['severed_relation'][1]}→ `{rem['severed_relation'][2]}`",
        (
            f"- Generator output: `{rem['artifact']['path']}` (sha256 `{rem['artifact']['sha256'][:16]}…`) — "
            "a generic guardrail template chosen from the target asset type; it is **not** a 1:1 "
            "implementation of the severed relation (known limitation, see docs/demo.md)"
        ),
        (
            "- Automated pre-approval: "
            f"`{findings['automated_preapproval']['status']}` "
            "(a recommendation only; a human decision is still required)"
        ),
        "",
        "## Controls exercised against the running API",
        "",
        "| Control | Request | Actor | Expected | Observed | Held |",
        "|---|---|---|---:|---:|:-:|",
    ]
    for c in findings["controls"]:
        lines.append(
            f"| {c['control']} | `{c['request']}` | {c['actor']} | {c['expected_status']} | "
            f"{c['observed_status']} | {'✓' if c['held'] else '✗'} |"
        )
    held = sum(c["held"] for c in findings["controls"])
    lines += [
        "",
        f"**{held}/{len(findings['controls'])} controls held.**",
        "",
        "## Reproduce and check",
        "",
        "```bash",
        "python -m art_sim.demo --out out/demo   # one command; offline; no credentials",
        "```",
        "",
        f"Findings digest (SHA-256 of `findings.json`): `{digest}`",
        "",
        (
            "The digest covers everything above. It is identical on every run and machine; the run "
            "prints `REPRODUCED` when it matches the value committed in the repository."
        ),
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------------- HTML

CSS = """
:root{--bg:#f7f8fa;--card:#fff;--fg:#1f2933;--muted:#52606d;--line:#d9dee4;--accent:#0b6bcb;
--good:#1f7a36;--bad:#b42318;--warn:#8a5a00;--bar:#0b6bcb;--chip:#eef2f6}
@media (prefers-color-scheme:dark){:root{--bg:#0e1217;--card:#161b22;--fg:#e6e9ee;--muted:#a3adb8;
--line:#2a323c;--accent:#58a6ff;--good:#56d364;--bad:#ff7b72;--warn:#e3b341;--bar:#58a6ff;--chip:#1f2630}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 56px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.sub{color:var(--muted);margin:0 0 14px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
.chip{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card .k{color:var(--muted);font-size:13px}.card .v{font-size:26px;font-weight:700;margin-top:2px}
.card .v small{font-size:13px;font-weight:500;color:var(--muted)}
.good{color:var(--good)}.bad{color:var(--bad)}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px}
.figs svg{max-width:100%;height:auto;display:block;border-radius:8px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:12px;overflow:hidden;font-size:14px}
th,td{padding:8px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--chip);font-weight:600}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}
.bar{height:8px;background:var(--chip);border-radius:4px;min-width:90px}
.bar i{display:block;height:100%;background:var(--bar);border-radius:4px}
code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--chip);padding:1px 5px;border-radius:4px}
pre{background:var(--chip);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;font-size:12.5px}
details{margin-top:10px}summary{cursor:pointer;color:var(--accent)}
.note{color:var(--muted);font-size:13px}.ok{color:var(--good);font-weight:600}.no{color:var(--bad);font-weight:600}
@media print{body{background:#fff}.card,.panel,table{break-inside:avoid}}
"""


def _inline(text: str) -> str:
    """Escape ``text`` and render `backtick` spans as <code>."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", e(text))


def _row(cells: list[str], *, header: bool = False, numeric: set[int] | None = None) -> str:
    tag = "th" if header else "td"
    numeric = numeric or set()
    return "<tr>" + "".join(
        f'<{tag}{" class=n" if i in numeric else ""}{" scope=col" if header else ""}>{c}</{tag}>'
        for i, c in enumerate(cells)
    ) + "</tr>"


def render_html(ev: DemoEvidence, findings: dict[str, Any], digest: str) -> str:
    """Self-contained HTML page: no scripts, no network resources."""
    ver, br, risk = findings["verification"], findings["blast_radius"], findings["risk"]
    held = sum(c["held"] for c in findings["controls"])
    total = len(findings["controls"])
    before_svg, after_svg = figures(ev)
    approval = ev.result.approval
    chain_ok = ev.audit_report.ok

    factor_rows = []
    for f in risk["factors"]:
        pct = 0 if f["maximum"] == 0 else min(100.0, abs(f["value"]) / f["maximum"] * 100)
        maximum = "—" if f["maximum"] == 0 else f"{f['maximum']:.0f}"
        factor_rows.append(
            _row(
                [
                    e(f["name"]),
                    f"{f['value']:+.2f}",
                    maximum,
                    f'<div class="bar" role="img" aria-label="{pct:.0f}% of maximum"><i style="width:{pct:.0f}%"></i></div>',
                    _inline(f["justification"]),
                ],
                numeric={1, 2},
            )
        )
    control_rows = [
        _row(
            [
                e(c["control"]),
                f"<code>{e(c['request'])}</code>",
                e(c["actor"]),
                str(c["expected_status"]),
                str(c["observed_status"]),
                f'<span class="{"ok" if c["held"] else "no"}">{"✓ held" if c["held"] else "✗ FAILED"}</span>',
                e(c["effect"]),
            ],
            numeric={3, 4},
        )
        for c in findings["controls"]
    ]
    event_rows = [
        _row(
            [
                e(event.timestamp.strftime("%H:%M:%S")),
                f"<code>{e(event.event_type)}</code>",
                e(event.actor),
                e(event.status),
            ]
        )
        for event in ev.operational_events
    ]
    security_rows = [
        _row(
            [
                e(event.timestamp.strftime("%H:%M:%S")),
                f"<code>{e(event.event_type.value)}</code>",
                e(event.subject or "—"),
                e(event.result),
            ]
        )
        for event in ev.security_events[-14:]
    ]
    checks = findings["automated_preapproval"]["checks"]
    check_items = "".join(f"<li>{'✓' if ok else '✗'} {e(name.replace('_', ' '))}</li>" for name, ok in checks.items())
    rem = findings["remediation"]
    artifact = ev.result.remediation_artifacts[0]
    tamper_issues = "; ".join(f"{i.kind} (line {i.line})" for i in ev.tamper_report.issues) or "none"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab Demonstration Report</title><style>{CSS}</style></head><body><main>
<h1>Autonomous Red Teaming — lab demonstration</h1>
<p class="sub">A fictional estate analysed end to end. Simulation only: nothing real was scanned, contacted or changed.</p>
<div class="chips"><span class="chip">Synthetic data</span><span class="chip">Human approval required</span>
<span class="chip">{held}/{total} controls held</span>
<span class="chip">Audit chain {"verified" if chain_ok else "BROKEN"}</span></div>

<section aria-label="Headline results" class="cards">
<div class="card"><div class="k">Risk score</div><div class="v">{ver["risk_before"]:.2f} → <span class="good">{ver["risk_after"]:.2f}</span> <small>/100</small></div></div>
<div class="card"><div class="k">Crown-jewel exposure</div><div class="v">{br["before"]["crown_jewel_exposure_percent"]:.0f}% → <span class="good">{br["after"]["crown_jewel_exposure_percent"]:.0f}%</span></div></div>
<div class="card"><div class="k">Blast radius</div><div class="v">{br["before"]["percent"]:.0f}% → {br["after"]["percent"]:.0f}% <small>{br["after"]["reachable_assets"]}/{br["after"]["total_assets"]} assets</small></div></div>
<div class="card"><div class="k">Verification</div><div class="v good">{e(ver["status"])}</div><div class="note">{ver["paths_removed"]} route removed, {ver["remaining_paths"]} remaining</div></div>
</section>

<h2>Before and after the approved control</h2>
<div class="figs panel">{before_svg}{after_svg}</div>
<p class="note">Same layout in both views. The red route is the shortest path from the internet to the crown jewel (★); the dashed edge is the single relation the approved control severs. Dashed boxes are no longer reachable from the entry point.</p>

<h2>Why the risk is {risk["score"]:.2f}</h2>
<div class="wrap"><table><thead>{_row(["Factor", "Points", "Max", "Share of max", "Evidence"], header=True, numeric={1, 2})}</thead><tbody>{"".join(factor_rows)}</tbody></table></div>
<p class="note">Each point value is the scorer's own output; the evidence column states the inputs behind it. Factors sum to the reported score: <strong class="{"ok" if risk["reconciles"] else "no"}">{"yes" if risk["reconciles"] else "NO"}</strong>.</p>

<h2>Proposed remediation — never applied</h2>
<div class="panel">
<p><strong>{e(rem["action"].replace("_", " "))}</strong>: sever <code>{e(rem["severed_relation"][0])}</code> —{e(rem["severed_relation"][1])}→ <code>{e(rem["severed_relation"][2])}</code>.
It was applied only to an in-memory copy of the graph to produce the "after" figure and the verification above.</p>
<p>Automated pre-approval: <strong>{e(findings["automated_preapproval"]["status"].replace("_", " "))}</strong> — a recommendation only.</p>
<ul>{check_items}</ul>
<details><summary>Generator output: <code>{e(artifact.file_path)}</code> (sha256 {e(artifact.content_sha256[:16])}…)</summary>
<p class="note">Known limitation: the policy generator picks a generic guardrail template from the target asset type. It is a review candidate, not a 1:1 implementation of the severed relation above; the verified effect comes from the graph simulation, not from this file.</p><pre>{e(artifact.content)}</pre></details>
</div>

<h2>Human approval</h2>
<div class="panel">
<p>Decision: <strong>{e(approval.decision.value) if approval else "none"}</strong> by <code>{e(approval.operator) if approval else "—"}</code>
at {e(approval.decided_at.strftime("%Y-%m-%d %H:%M:%S UTC")) if approval else "—"}.</p>
<p>Reason recorded: “{e(approval.reason) if approval else ""}”</p>
<p class="note">The worker refused to verify or publish anything until the decision carried a valid HMAC bound to this run, operator, decision and time. Before the decision the result endpoint answered 409: no result exists without a human.</p>
</div>

<h2>Controls exercised against the running API</h2>
<div class="wrap"><table><thead>{_row(["Control", "Request", "Actor", "Expected", "Observed", "Result", "Effect"], header=True, numeric={3, 4})}</thead><tbody>{"".join(control_rows)}</tbody></table></div>

<h2>Audit evidence <span class="note">(this execution)</span></h2>
<div class="figs">
<div><h3>Operational events — run {e(str(ev.run.run_id)[:8])}…</h3><div class="wrap"><table><thead>{_row(["Time", "Event", "Actor", "Status"], header=True)}</thead><tbody>{"".join(event_rows)}</tbody></table></div></div>
<div><h3>Security audit (latest {len(ev.security_events[-14:])})</h3><div class="wrap"><table><thead>{_row(["Time", "Event", "Subject", "Result"], header=True)}</thead><tbody>{"".join(security_rows)}</tbody></table></div></div>
</div>
<p>Hash chain of the durable security log: <strong class="{"ok" if chain_ok else "no"}">{"intact" if chain_ok else "BROKEN"}</strong>
({ev.audit_report.chained_events} chained events, seq {ev.audit_report.first_seq}–{ev.audit_report.last_seq}).
Deleting one event from a copy is detected: <strong class="ok">{e(tamper_issues)}</strong>.</p>

<h2>Reproduce and check</h2>
<div class="panel">
<pre>python -m art_sim.demo --out out/demo</pre>
<p>Findings digest (SHA-256 of <code>findings.json</code>):</p><pre>{e(digest)}</pre>
<p class="note">The digest covers the graph, route, risk factors, blast radius, remediation, verification and every control outcome. It is identical on every run and machine. Run IDs, timestamps and the audit log above are per-execution evidence and are deliberately excluded.</p>
</div>
</main></body></html>
"""


# ------------------------------------------------------------------------------- writing


def write_artifacts(ev: DemoEvidence, out: Path) -> tuple[str, dict[str, Path]]:
    """Write every output file under ``out`` and return the digest and the file map."""
    findings = build_findings(ev)
    digest = findings_digest(findings)
    before, after = figures(ev)
    files = {
        "findings.json": out / "findings.json",
        "findings.sha256": out / "findings.sha256",
        "report.md": out / "report.md",
        "report.html": out / "report.html",
        "before.svg": out / "before.svg",
        "after.svg": out / "after.svg",
        "worker-report.md": out / "worker-report.md",
        "audit-verification.txt": out / "audit" / "verification.txt",
    }
    files["findings.json"].write_text(canonical(findings), encoding="utf-8")
    files["findings.sha256"].write_text(f"{digest}  findings.json\n", encoding="utf-8")
    files["report.md"].write_text(render_markdown(ev, findings, digest), encoding="utf-8")
    files["report.html"].write_text(render_html(ev, findings, digest), encoding="utf-8")
    files["before.svg"].write_text(before, encoding="utf-8")
    files["after.svg"].write_text(after, encoding="utf-8")
    files["worker-report.md"].write_text(ev.result.report_markdown, encoding="utf-8")
    files["audit-verification.txt"].write_text(
        f"security log: ok={ev.audit_report.ok} chained={ev.audit_report.chained_events} "
        f"seq={ev.audit_report.first_seq}..{ev.audit_report.last_seq} head={ev.audit_report.head_hash}\n"
        f"tamper demo (one event deleted from a copy): ok={ev.tamper_report.ok} "
        f"issues={[(i.kind, i.line) for i in ev.tamper_report.issues]}\n",
        encoding="utf-8",
    )
    # Hashes of the reproducible files only: a reviewer's run must match these byte for byte.
    reproducible = ("findings.json", "report.md", "before.svg", "after.svg")
    (out / "REPRODUCIBLE.sha256").write_text(
        "".join(f"{sha256(files[name].read_bytes()).hexdigest()}  {name}\n" for name in reproducible),
        encoding="utf-8",
    )
    return digest, files
