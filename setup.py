"""Legacy setup.py shim for GhostWall.

Modern packaging metadata lives in pyproject.toml. This file remains for
backwards compatibility with older tooling that expects a setup.py.
"""

from __future__ import annotations

from setuptools import setup

setup()
