# Governed sandbox policy binding

This source addition passed a normal Maven source build and its maintained tests using framework 26.10.23. It is not a qualified deployment, published SDK, insurance coverage bind, carrier issuance, or accounting acceptance.

The build used the [source parent fixture](https://github.com/fireflysoftwaresolutions/firefly-parent/commit/6442bd51733ade4d5f4583e1afe812dd2c520b40) with released framework 26.10.23 and the original producer-derived Underwriting SDK input. This does not establish adoption of a newly published OpenPlatform parent or policy SDK; the repository parent version remains unchanged.

The first scope records the existing illustrative sandbox property quote. Its original wording says acceptance does not bind insurance coverage. A resulting `BOUND` policy is a governed sandbox record; `IN_FORCE` is local sandbox activation. Mastered policy/contract documents and actual premium/accounting effects are separate unfinished work. The existing TERM_PC product program is not translated into illustrative deductible/rating values by this slice.

## API contract

The `GovernedPolicies` tag declares `bindGovernedPolicy`, `recoverGovernedPolicyBinding` and `issueGovernedPolicy`, each with explicit bearer requirements and typed JSON200 output. Requests contain stable action IDs and exact reference/version/digest intent. They do not contain tenant, actor, privilege, premium or authoritative receipt values. Core independently checks current identity/PDP and obtains accepted terms from the protected original Underwriting current/recovery operations through the official generated SDK.

Binding requires an existing active customer contract, a current active party/role relationship and matching product, currency and period. There is no create/attach fallback. The Contract DTO does not contain a tenant ID: the first scope therefore requires an explicitly configured, server-owned dedicated deployment binding. It does not establish general multitenant contract ownership. The authenticated CoreContract receiver/official SDK integration remains a separate prerequisite.

Write outcomes are `COMMITTED`, `COMMITTED_RESPONSE_UNAVAILABLE`, `OUTCOME_UNKNOWN` and `REFUSED`. Only `COMMITTED` includes a privileged result. An uncertain result keeps the original action/intent identity; it is not a generic503 invitation to mint another action. Protected recovery returns `FOUND`, `NOT_OBSERVED_AT_THIS_READ` or `INTENT_CONFLICT`; absence at one read is not proof that a concurrent or earlier action cannot commit. Historical replay preserves the original immutable receipt, including its original policy status/version, rather than reinterpreting it as the latest status.

## Owner boundaries

Only Core owns the policy, party, new-business transaction, coverage, status history, operation, immutable accepted-terms snapshot and receipt. Assigned inserts require exactly one affected row. Activation compares tenant, actor, policy ID, state, original version, receipt and immutable identity before updating. Domain orchestrates official generated clients and owns no business store.

The canonical immutable audit append, actual two-role PDP decision IDs/revisions, scoped effect rows and receipt use the same verified connection-factory/client/template/transaction-manager graph and owner root. Missing provenance or append failure cannot become a successful write. Source-level controlled transaction fixtures are not proof of PostgreSQL commit, ACL, triggers or physical connection release.

The supported native Spring token-exchange grant preserves the original verified HUMAN subject and current party. It has no actor-token invention, machine-as-human substitution, raw multi-audience relay or staff-to-party conversion. The returned token is natively decoded and checked before its generated bearer authentication is attached to a new caller-owned client. Real provider authorization/token-exchange acceptance is still required. The explicit first profile uses an already-declared UUID tenant sandbox; authoritative opaque platform-namespace mapping remains separate and is never implemented by parsing or hashing an opaque string.

The original wall/monotonic admission window is at most five seconds and is not renewed during remote reads or database work. The owner scope closes eagerly before downstream publication. A final elapsed-window check cannot reveal a committed result after the window; known commit becomes response-unavailable and an unproven outcome remains unknown.

## Activation and remaining gates

`insurance.policies.governed.enabled` defaults off. Even when explicitly enabled, composition requires the concrete current admission adapter, caller-bound quote/contract transports and explicitly named verified owner resources. No business connection factory, permissive policy, client identity, local-state fallback or configuration mapping is inferred. Missing trusted composition leaves the controller at503 before business invocation.

The Java store calls fixed owner `verify_protocol` and `verify_receipt` integrity functions. The optional V4 schema installer source exists outside ordinary migration discovery; its canonical bridge, deferred integrity guards and runtime readiness functions are not yet implemented. None of this owner SQL has been executed. There is no automatic DDL, role creation or grant. Do not enable this feature until that source, native protocol and owned PostgreSQL gates are complete. Existing V1-V3 SQL and normal migration locations remain unchanged.

Compilation, controlled transaction and authority fixtures, and the original mock OpenAPI producer tests passed in the source build. The current Contract SDK exposes generic party pagination: this adapter refuses entries that are not the exact generated party DTO type. The new protected Contract receiver and its genuinely regenerated SDK remain separate prerequisites. Governed Core and Domain policy SDK generation, stricter API/origin gates, provider exchange, PostgreSQL/restart and the complete Experience-to-Domain-to-Core journey remain open. No checked-in generated specification or SDK is hand-edited.
