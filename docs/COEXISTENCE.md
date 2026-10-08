# Compatibility and coexistence with nexus-legacy

Moved from the README. Content unchanged.

`nexus-core` and the current `nexus-legacy` package in `Nexus-new` have distinct package and console-script ownership:

- Nexus Core is distributed as `nexus-certify` while continuing to own the internal `product` Python package and `nexus-certify` console script.
- `nexus-legacy` owns the `nexus` and `scripts` packages and the `nexus` console script.

Use separate virtual environments for normal development and testing because the repositories have different dependency sets and operational roles.
