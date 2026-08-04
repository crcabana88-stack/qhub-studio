# R15.6.4 — Managed-Role Access Diagnostic: what it is and what it is not

Offline analysis. Nothing in this document or in diagnostic `28` authorizes execution of anything.
**RECORD 26 and POST 27 remain unauthorized.**

## 1. What the authorized live PRE 25 discovered

PRE 25 was executed read-only against project `jsjsanmaahvmynblmzkq` at commit
`fe0558dfe194525089159aaa9ce8b6fe9eb1922d` (artifact SHA-256
`bf7b9c1331ffb6b845fd8fcebd159786b62b9d28d0bf0b6787967f055632f627`). It returned:

```
verdict = UNEXPECTED_MIGRATION_HISTORY_STOP
no_unauthorized_access_path = false
unauthorized_access_paths   = {cli_login_postgres, supabase_etl_admin, supabase_read_only_user}
```

**Exactly one condition failed.** Everything else verified: the commercial verifier held its
complete reviewed authority and returned `product_ready = true`, `product_version =
2026-07-30.commercial-launch-r8`, `product_failed_count = 0`; the history table matched the pinned
CLI contract in every dimension; `nspacl` and `relacl` were empty; `anon`, `authenticated` and
`service_role` held nothing; there were no malformed, newer, conflicting, or existing `20260729`
rows (`target_rows = 0` — history is still unrecorded, as expected).

So the gate did its job: it refused to authorize a write because three login roles can reach the
migration-history objects, and nothing in the reviewed evidence explains what they are.

## 2. Why these three roles are not being automatically trusted

`cli_login_postgres`, `supabase_etl_admin` and `supabase_read_only_user` *look* like
Supabase-managed platform identities. That is an inference from their names, and a name is not a
capability. Concretely:

- A role name is not access-controlled. Any role can be created with any non-`pg_`-prefixed name.
- The observed names are not documented anywhere in this repository, so the package has no
  authoritative evidence of what they are or who controls them.
- The three roles differ from each other in kind. The live PRE reports only that each *reaches*
  the objects — not whether that is read or write, direct or inherited, or whether any of them can
  additionally assume the contract owner or a superuser. Those distinctions change the risk
  completely, and none of them are visible yet.
- Accepting them because they look managed is precisely the failure mode this release loop has
  rejected four times: weakening a check so a live run turns green.

**No exception is being granted here.** The package's mandatory predicate is unchanged, and this
task adds no name whitelist, no `pg_`-prefix exemption, and no relaxation of any gate.

## 2b. MEMBER, USAGE and SET are three different things (correction)

The first revision of diagnostic 28 used `pg_has_role(candidate, role, 'MEMBER')` as proof that a
candidate could inherit the role's privileges or execute `SET ROLE`. **That was materially
inaccurate.** PostgreSQL 16 records three independent properties per membership
(`pg_auth_members.admin_option`, `.inherit_option`, `.set_option`) and exposes three distinct
`pg_has_role` privilege names. Measured on PostgreSQL 16, including real `SET ROLE` attempts:

| membership grant | MEMBER | USAGE | SET | `has_table_privilege` | actual `SET ROLE` | actual `SELECT` |
|---|---|---|---|---|---|---|
| `INHERIT FALSE, SET FALSE` | t | f | f | no | **DENIED** | denied |
| `INHERIT FALSE, SET TRUE` | t | f | **t** | no | **allowed** | denied until `SET ROLE` |
| `INHERIT TRUE, SET FALSE` | t | **t** | f | **yes** | **DENIED** | allowed |
| `INHERIT TRUE, SET TRUE` | t | t | t | yes | allowed | allowed |
| `ADMIN TRUE` only | t | f | f | no | **DENIED** | denied |

So:

- **MEMBER** means only that a membership path exists. On its own it is an **inactive
  membership**: it confers no privilege and no `SET ROLE` authority.
- **USAGE** means the role's privileges apply *without* `SET ROLE`. This is what
  `has_schema_privilege` / `has_table_privilege` already follow, which is why those functions are
  the authority for "usable without SET ROLE".
- **SET** means `SET ROLE` is permitted. Only roles with SET are described as *settable*; the word
  "assumable" has been removed from the diagnostic entirely.
- **ADMIN OPTION** permits re-granting the membership. It is reported, but it is never used in any
  reachability predicate — it proves neither inheritance nor `SET ROLE`.

Transitive paths compose per edge: a path permits inheritance only if **every** edge on it has
`inherit_option`, and permits `SET ROLE` only if every edge has `set_option`. A candidate may hold
several paths to the same role with conflicting options; the diagnostic reports each path as its
own row and never collapses them into a single misleading boolean. Cycles are prevented by
excluding any role already on the path, with depth capped at 16. Every path row also carries the
authoritative `pg_has_role` MEMBER/USAGE/SET values for its end role, so path arithmetic can be
cross-checked against PostgreSQL itself — the test suite asserts the path evidence never claims
more than the server allows.

**Effect on the gate.** PRE 25 / RECORD 26 / POST 27 use the MEMBER closure. Under these
semantics that predicate is **conservative**: it can flag an inactive membership that confers
nothing, so it may over-block but can never under-block. It remains fail-closed and is
deliberately left unchanged by this correction; the diagnostic exists to give a reviewer the
precise picture needed to interpret a STOP.

## 3. What the diagnostic collects

`28_READ_ONLY_MANAGED_ROLE_DIAGNOSTIC.sql`
(SHA-256 `b69a72a915f5bb37ad3ec7f3591e9ed4f392f44fc2f3d1021f73e9977134862f`)
is one explicit `REPEATABLE READ, READ ONLY` transaction containing no mutating SQL, no temporary
objects and no dynamic SQL. Candidates are discovered from `pg_roles` — the three observed names
appear nowhere in its executable text. It returns **five** ordered result sets:

| Query | Evidence |
|---|---|
| 1 | Protected-object identity: schema and table owner, `nspacl`, `relacl`, RLS state, the pinned contract owner, default-ACL entries scoped to `supabase_migrations`, superuser and total role counts, server version. |
| 2 | Candidate inventory: `LOGIN`, `SUPERUSER`, role-default `INHERIT`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`, connection limit; **exact role validity** (`rolvaliduntil`, `never_expires`, `currently_valid`, `expired`); and the three separated reachability facts — `privileges_usable_without_set_role`, `privileges_via_set_role`, and `reaches_protected_objects` (their disjunction). Owner and superuser exposure is likewise split into `can_set_role_to_*` (SET), `inherits_from_*` (USAGE) and `inactive_membership_of_pinned_owner` (MEMBER only). Role sets are reported as `roles_inherited_from`, `roles_settable_via_set_role` and `roles_inactive_membership_only`, with the predefined `pg_*` roles split the same three ways. |
| 3 | **The core route table** — one row per (candidate, object, privilege) reached by any route, plus rows where only an inactive membership exists (both reach flags false). Columns: `usable_without_set_role`, `reachable_via_set_role`, `inactive_membership_only`, `held_directly_or_inherited_by_self`, `inheriting_roles`, `settable_roles`, `inactive_membership_roles`, `via_predefined_role_inherited`, `via_predefined_role_settable`, `via_owner_role_inherited`, `via_owner_role_settable`, `via_explicit_acl`, `via_public_grant`. Covers schema `USAGE`/`CREATE` and table `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`REFERENCES`/`TRIGGER`. |
| 4 | **Membership paths** — every direct and transitive route, one row per path: candidate, edge member role, edge granted role, grantor, `edge_admin_option`, `edge_inherit_option`, `edge_set_option`, `path_depth`, the readable `path`, a deterministic `path_identity` (the OID chain), `path_permits_inheritance`, `path_permits_set_role`, whether the granted role is predefined/login/superuser/the pinned owner, and the authoritative `pg_has_role` MEMBER/USAGE/SET values for the path's end role. Conflicting paths appear as separate rows; cycles are excluded; depth is capped at 16. |
| 5 | **Structured ACL evidence** — one row per explicit ACL entry on the protected schema and table: object type and identity, grantee OID and name, `grantee_is_public`, grantor OID and name, privilege type, grantability. Empty output means both ACLs are NULL, which is the pinned contract. |

It reads only `pg_roles`, `pg_auth_members`, `pg_namespace`, `pg_class`, `pg_default_acl` and
PostgreSQL's privilege functions. It reads **no application rows**, no `auth` or `storage` schema,
no secrets, tokens, credentials or customer data, and no schema other than `supabase_migrations`
(the pinned-owner lookup reads `pg_class` metadata for `public.qhub_manual_review_requests`, never
a row from it).

## 4. Which results would remain blocking

The diagnostic produces **evidence, not a verdict**. On review, these outcomes keep the gate shut:

- Any candidate with **write** reach (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`) — whether usable
  without `SET ROLE` or reachable via `SET ROLE`. Migration history is an integrity record; a role
  that can rewrite it can forge the applied-migration story.
- Any candidate that can **`SET ROLE` to the pinned owner or a superuser**
  (`can_set_role_to_pinned_owner` / `can_set_role_to_a_superuser`), or that **inherits** from
  either (`inherits_from_*`) — that is full authority over the protected objects and the verifier.
  An `inactive_membership_of_pinned_owner` is evidence to investigate, not access in itself.
- Any candidate reaching the objects through an **explicit ACL entry** on the schema or table:
  the pinned contract is `nspacl IS NULL` and `relacl IS NULL`, so such an entry is unexplained
  configuration drift regardless of who holds it.
- Any **`PUBLIC`** grant.
- Any candidate whose identity cannot be tied to a documented platform mechanism — including a
  role that merely *looks* managed.
- Any `set_role_only` path that a reviewer cannot attribute to a controlled operator workflow.

A path could only stop being blocking if a reviewer establishes, from authoritative platform
documentation or the provider directly, (a) exactly which capabilities the role holds here, and
(b) that the identity is genuinely provider-controlled infrastructure with no customer-reachable
credential. That is a human determination requiring evidence this repository does not yet contain.

## 5. If an exception is ever granted

It must be expressed as a **precisely verified capability and identity**, not a name pattern:
narrow, per-role, per-privilege, and re-verified at execution time. Specifically prohibited:

- a broad `pg_`-prefix or `supabase_`-prefix exemption;
- an unconditional role-name whitelist;
- any change that lets a role with write access, owner assumption, or an explicit ACL entry pass;
- editing the gate to make the current live state green without first explaining it.

Until such an exception is separately reviewed and authorized, the mandatory predicate stands as
implemented, and PRE 25 will continue to return `UNEXPECTED_MIGRATION_HISTORY_STOP`.

## 6. Status

- Diagnostic 28: corrected for the PostgreSQL 16 MEMBER/USAGE/SET distinction, offline-validated
  on disposable localhost PostgreSQL 16 against twelve adversarial membership shapes and against
  **actual `SET ROLE` success and denial**, and **not executed against any live or remote
  database**.
- PRE 25 / RECORD 26 / POST 27, the commercial migration, and the statements fixture: **unchanged**
  (hashes re-verified).
- **PRE 25, RECORD 26, POST 27 and diagnostic 28 all remain unauthorized for further live
  execution.** The earlier PRE 25 run was a single, separately authorized read-only execution; it
  conferred no standing permission. A future authorization for 28 would cover 28 alone.
- Diagnostic output is **evidence only**. It contains no verdict, approves nothing, and must not
  be treated as clearing any role.
