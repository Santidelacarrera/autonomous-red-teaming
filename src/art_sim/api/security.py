"""Backward-compatible exports for the Phase-8 HTTP composition boundary."""

from art_sim.security.identity import ApiRole, Authenticator, Identity, Principal
from art_sim.security.providers.development import DevelopmentHeaderAuthenticator

__all__ = ("ApiRole", "Authenticator", "DevelopmentHeaderAuthenticator", "Identity", "Principal")
