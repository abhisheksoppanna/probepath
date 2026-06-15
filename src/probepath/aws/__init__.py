"""AWS semantics, isolated and auditable.

A security reviewer can validate probepath's correctness by reading this package plus
``engine/reachability.py`` and nothing else. Per the layering rule, ``aws`` never imports
from ``engine`` (DESIGN.md §4.1).
"""
