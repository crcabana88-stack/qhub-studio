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

## 3. What the diagnostic collects

`28_READ_ONLY_MANAGED_ROLE_DIAGNOSTIC.sql`
(SHA-256 `659608f7640dba42e3f025acabd2327227381cd23be9bb25e901091bba611005`)
is one explicit `REPEATABLE READ, READ ONLY` transaction containing no mutating SQL, no temporary
objects and no dynamic SQL. Candidates are discovered from `pg_roles` — the three observed names
appear nowhere in its executable text. It returns four ordered result sets:

| Query | Evidence |
|---|---|
| 1 | Protected-object identity: schema and table owner, `nspacl`, `relacl`, RLS state, the pinned contract owner, default-ACL entries scoped to `supabase_migrations`, superuser and total role counts. |
| 2 | Candidate inventory: `LOGIN`, `SUPERUSER`, `INHERIT`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`, connection limit, validity; whether the candidate reaches the protected objects; whether it can assume the pinned owner or any superuser; which predefined `pg_*` roles it can reach; and the full set of roles it can assume. |
| 3 | **The core evidence table** — one row per (candidate, privilege) actually reached, attributing the route: `direct_or_inherited` vs `set_role_only` (the NOINHERIT/`SET ROLE` case), `via_predefined_role`, `via_owner_role`, `via_explicit_acl`, `via_public_grant`, and the exact `granting_roles`. Covers schema `USAGE`/`CREATE` and table `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`REFERENCES`/`TRIGGER`. |
| 4 | Membership edges: each direct `GRANT role TO candidate`, its grantor, admin option, whether the granted role is predefined/login/superuser, and whether it applies without `SET ROLE`. |

It reads only `pg_roles`, `pg_auth_members`, `pg_namespace`, `pg_class`, `pg_default_acl` and
PostgreSQL's privilege functions. It reads **no application rows**, no `auth` or `storage` schema,
no secrets, tokens, credentials or customer data, and no schema other than `supabase_migrations`
(the pinned-owner lookup reads `pg_class` metadata for `public.qhub_manual_review_requests`, never
a row from it).

## 4. Which results would remain blocking

The diagnostic produces **evidence, not a verdict**. On review, these outcomes keep the gate shut:

- Any candidate with **write** reach (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`) — migration history
  is an integrity record; a role that can rewrite it can forge the applied-migration story.
- Any candidate that **can assume the pinned owner or a superuser** (`can_assume_pinned_owner` /
  `can_assume_a_superuser`) — that is full authority over the protected objects and the verifier.
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

- Diagnostic 28: built, offline-validated on disposable localhost PostgreSQL 16, **not executed
  against any live or remote database**.
- PRE 25 / RECORD 26 / POST 27, the commercial migration, and the statements fixture: **unchanged**.
- RECORD 26 and POST 27: **unauthorized**. A future authorization for 28 covers 28 alone.
