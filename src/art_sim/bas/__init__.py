"""Breach-and-attack simulation (BAS) for the platform's own trust boundaries.

A controlled, self-contained harness: attack cases run **in process** against a synthetic
two-tenant lab (ASGI transport, throw-away stores, loopback-only PostgreSQL). Nothing here
opens a network connection to a target, and the lab holds no real data. Every attempt is
recorded by AegisTrace as a tamper-evident forensic incident. See ``docs/bas.md``.
"""
