# Reconciliation with the inherited main line

This change reconciles runnable candidate `a8b3c1795a45486e75386fa2c3a8225c14293845` with main `92894aa52de06f2f4ba7d5f234a0a55f93314474`. The merge preserves both histories. It does not treat the main-line rollback to an earlier 19-package snapshot as a technical replacement for the current 43-package implementation.

## Resolution decisions

| Surface | Decision and reason |
|---|---|
| Workspace, lockfile and 21 domain packages removed by the historical rollback | Preserve the current complete 43-package workspace, reviewed pinned dependency graph and all executable source. The service depends on the current implementation and its tests. |
| README, current portal, module index and V2 truth files | Keep the current V2.1 entry, structural package coverage and explicit capability gaps. Historical V1.4.4 19-package coverage remains a frozen inherited measurement. |
| Historical module guides and validators | Keep the current source-bound API inventories and generation-aware historical validation. No historical receipt is promoted to current evidence. |
| Workflow trust, external-admission objects and repository tests removed by the rollback | Preserve the strict current gates, denial tests, schemas and false-authority boundary. |
| H02 artifact paths | Keep the current fixed, bounded artifact destinations; do not reintroduce executable environment/path dependence removed by the trust hardening. |
| V1.4.4 documentation workflow trigger | Retain main's removal of the obsolete branch exclusion. The workflow remains read-only and uses the current generation-aware validator. |
| Legal and security policy | Preserve all restrictions and private reporting obligations. Document historical H00-WP06 / H00-WP07 as aliases of current HB-BLK-EXT-001 / HB-BLK-EXT-003. No signed legal disposition or qualified reporting channel is fabricated. |

The historical V1.4.6 recovery contract remains applicable to its inherited modules: before-entry provider/fence failures are distinct from outcome unknown after publication, and both target and anchor require reconciliation where that protocol applies. Current service behavior is specified separately in its module guide; the inherited contract is not evidence that the new server already integrates an external rollback anchor.

## Unadmitted runner-probe history

Main introduced `self-hosted-desktop-availability.yml` in commit `1c69131`. Its original bytes are retained solely as `docs/operations/history/self-hosted-desktop-availability-1c69131.yml.disabled`. It is outside `.github/workflows` and cannot execute as a GitHub Actions workflow.

The original probe interpolates an untrusted manual input directly into a shell script and requests a self-hosted runner outside the current workflow-admission profile. Its runtime checks occur after runner allocation. It must not be copied back into an active workflow or executed as-is. Future runner qualification requires a separately reviewed design that passes the existing trust rules; this merge adds no runner exception and weakens no validator. The archived file proves what main contained, not that its invocation is safe or admitted.

## Authority and verification

Source integration, local tests and CI do not establish independent review, legal disposition, operational qualification or a compatibility claim. Verification must bind the actual merged source and its prospective final merge, rather than either parent's historical result.

```text
qualification: false
compatibility_claim: false
production_authority: false
migration_authority: false
release_authority: false
authority_effect: NONE
```
