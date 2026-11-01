# Optional governed policy owner installation

This contract describes unexecuted installer source. It is not permission to install on an existing database and is not PostgreSQL, provider or financial journey acceptance. The application feature remains disabled by default. `IN_FORCE` records sandbox activation, not carrier issuance, mastered documents or premium/accounting effects.

## Fresh deployment prerequisites

Use an explicitly governed installation session for the actual policy database. Ordinary application Flyway discovery remains `classpath:db/migration` and installs the unchanged V1–V3 baseline. Neither V4 nor V5 belongs in that location. Do not change Flyway history, skip validation, repair checksums or adopt unknown schemas/rows to make these installers succeed.

The original policy tables must share their original restricted nonlogin owner. The separate `insurance_policy_binding_guard`, released canonical `firefly_audit_guard`, and `firefly_audit_writer` roles must already exist with the exact restricted attributes checked by the installers. Writer and guards must have no role memberships. The installer requires explicit SET and inherited object privileges for each required owner; these are owner-admin prerequisites, not application permissions. No role or membership is created by V4 or V5. The application never receives an owner or installer credential.

In the same database, independently install and validate the immutable audit schema and completed accessor from released framework 26.10.23. Use that release's original `db/optional/immutable-audit/postgresql.sql` and `completed-append.sql`, their original owner/ACL requirements, and their exact canonical helper bodies. V5 refuses incompatible helpers. An unrelated service's audit schema or an old runtime receipt is not a substitute for the actual policy database deployment.

Apply the unchanged `V4__Governed_Policy_Binding.sql` using the original policy owner session with explicit delegation to the policy guard. V4 creates fresh, empty custody schemas and grants no runtime access. Then apply `V5__Governed_Policy_Integrity.sql` through the explicitly delegated original owner. V5 refuses populated or partial custody; it does not upgrade, delete or import unknown business state. Keep the original schema-history schema/table and governed deployment record if an installation tool tracks these optional scripts. Never silently switch between automatic and manual history resolution.

## Privilege and integrity boundary

V5 adds two audit-guard-owned, fixed-search-path functions. Only the policy guard receives EXECUTE. The policy writer receives no new audit SELECT, audit-private USAGE or owner membership. Temporary audit-event REFERENCES is limited to the four same-tenant event foreign keys and is revoked before installation acknowledgment.

The explicit manual installation grants writer SELECT/INSERT on the five existing policy effect tables and three custody tables, UPDATE on only the two policy status/time fields and four binding CAS fields, and EXECUTE on the two integrity entry points. These grants are checked alongside role attributes, function bodies, signatures, ACLs, table owners, exact FK columns and enabled deferred/before triggers. They are not automatic feature activation. This contract does not claim row-level confidentiality for the original policy schema; the initial scope is a dedicated, server-bound deployment.

New writes require the same transaction/backend/session's unexpired, completed NEW canonical append. Receipt verification recomputes the immutable quote, both retained decision identities/revisions, phase intent, paired effect and result digest. BIND uses stream position one; activation uses position two and the exact canonical BIND predecessor. Authorization and admission decisions remain distinct, and each phase uses its own original admission revision. Historical receipt verification checks permanent canonical evidence without creating or reopening append authority. It preserves a BOUND receipt after later activation.

## Runtime and engine gates

Configure the application writer with UTC timezone and the actual single owned connection-factory/client/template/transaction-manager graph. Missing trusted admission, product/quote/contract transports or owner resources still refuses before business effects. A true readiness result is a technical deployment check, not current human/PDP authority. Provider/token-exchange and contract/quote reads retain their separate acceptance gates.

Before activation, a fresh owned PostgreSQL gate must apply the exact baseline and both optional scripts, execute the actual SpringData/root/appender store, and prove bind/replay/activation/historical recovery plus mutation, cross-scope, metadata and rollback negatives. The gate must retain actual source/JAR/native inputs and cleanup proof. No installer, role change, database or native test has run for this source candidate. Never transfer a previous banking engine result to this policy scope.
