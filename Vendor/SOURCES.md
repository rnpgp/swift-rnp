# Vendored Dependencies

## RNPFramework.xcframework

Built by `scripts/build-rnp-framework.sh` from:

| Component | Version / Ref | SHA-256 (tarball) | License | Source |
|---|---|---|---|---|
| rnp | v0.18.1 | `8133cb825e6672725b33f93b8f4185d702b7444c58240f00d9f3dc886f5b0aae` | BSD-2-Clause | https://github.com/rnpgp/rnp |
| Botan | 3.10.0 | `28a98475e05dc2052654397207b4a78e36e6309b662f7f2888feb78cc948cea6` | BSD-2-Clause | https://github.com/randombit/botan |
| json-c | json-c-0.18-20240915 | `3112c1f25d39eca661fe3fc663431e130cc6e2f900c081738317fba49d29e298` | MIT | https://github.com/json-c/json-c |
| sexpp | c641a2f36520bab783657a58650d9fda548b9dec | N/A (git submodule) | BSD-2-Clause | https://github.com/rnpgp/sexpp |

See [`docs/DEPENDENCIES.md`](../docs/DEPENDENCIES.md) for the dependency update policy, CVE response process, and review rules.

A dependency summary is bundled in the application About → Licenses view. Full license texts must be added to the target's bundle resources before binary distribution to satisfy the licenses of the vendored components.
