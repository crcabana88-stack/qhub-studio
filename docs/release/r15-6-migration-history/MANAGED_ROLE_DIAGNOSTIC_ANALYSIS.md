# R15.6.6 — Bounded Managed-Role Access Diagnostic: what it is and what it is not

Offline analysis. Nothing in this document or in diagnostic `28` authorizes execution of anything.
**PRE 25, RECORD 26, POST 27 and diagnostic 28 all remain unauthorized for live execution.**

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
  rejected repeatedly: weakening a check so a live run turns green.

**No exception is being granted here.** The package's mandatory predicate is unchanged, and this
task adds no name whitelist, no `pg_`-prefix exemption, and no relaxation of any gate.

## 3. MEMBER, USAGE and SET are three different things

The first revision of diagnostic 28 used `pg_has_role(candidate, role, 'MEMBER')` as proof that a
candidate could inherit the role's privileges or execute `SET ROLE`. **That was materially
inaccurate.** PostgreSQL 16 records three independent properties per membership
(`pg_auth_members.admin_option`, `.inherit_option`, `.set_option`) and exposes three distinct
`pg_has_role` privilege names. Measured on PostgreSQL 16, including real `SET ROLE` attempts from
sessions **authenticated as the candidate role itself**:

| membership grant | MEMBER | USAGE | SET | `has_table_privilege` | actual `SET ROLE` | actual `SELECT` |
|---|---|---|---|---|---|---|
| `INHERIT FALSE, SET FALSE` | t | f | f | no | **DENIED** | denied |
| `INHERIT FALSE, SET TRUE` | t | f | **t** | no | **allowed** | denied until `SET ROLE` |
| `INHERIT TRUE, SET FALSE` | t | **t** | f | **yes** | **DENIED** | allowed |
| `INHERIT TRUE, SET TRUE` | t | t | t | yes | allowed | allowed |
| `ADMIN TRUE` only | t | f | f | no | **DENIED** | denied |

So:

- **Direct / self authority** — the candidate holds the privilege itself (its own ACL entry, its
  own ownership, or `PUBLIC`). No membership is involved at all.
- **MEMBER** means only that a membership path exists. On its own it is an **inactive
  membership**: it confers no privilege and no `SET ROLE` authority.
- **USAGE** means the role's privileges apply *without* `SET ROLE`. This is what
  `has_schema_privilege` / `has_table_privilege` already follow, which is why those functions are
  the authority for "usable without SET ROLE".
- **SET** means `SET ROLE` is permitted. Only roles with SET are described as *settable*; the word
  "assumable" has been removed from the diagnostic entirely.
- **ADMIN OPTION** permits re-granting the membership. It is reported, but it is never used in any
  reachability predicate — it proves neither inheritance nor `SET ROLE`.

**Active and inactive routes coexist.** A candidate may hold several memberships to the same role,
or to different roles supplying the same privilege, with conflicting options. The diagnostic never
collapses them: every direct grant is its own row in the edge inventory (§4), the holder arrays in
the route table are separated by route kind, and `inactive_membership_only` is true **only** when
inactive evidence exists *and* there is no direct/self, USAGE, or SET route for that candidate and
privilege.

**Effect on the gate.** PRE 25 / RECORD 26 / POST 27 use the MEMBER closure. Under these
semantics that predicate is **conservative**: it can flag an inactive membership that confers
nothing, so it may over-block but can never under-block. It remains fail-closed and is
deliberately left unchanged; the diagnostic exists to give a reviewer the precise picture needed
to interpret a STOP.

## 4. Membership evidence is bounded — exhaustive path enumeration is withdrawn

This section has been rewritten twice, and the history matters because it explains why the current
design is the way it is.

**R15.6.4** capped the recursive membership walk at `depth < 16`. The second review constructed a
valid **17-edge** chain whose terminal role held real access, and the cutoff silently hid the whole
route. That was a genuine completeness defect.

**R15.6.5** removed the cutoff and emitted one row per distinct simple path. The third review
showed that this trades a correctness bug for an operational one: the number of simple paths is
exponential in the *shape* of the graph, not merely large. On a disposable fixture of **33 roles
and 116 membership edges** — one login role feeding eight fully connected layers of four roles —
there are exactly Σ 4^k for k = 1..8 = **87,380** simple paths, at a maximum depth of only 8. A
count-only aggregate over them spilled 13 temporary files and ~85.7 MB; the committed query would
have returned all 87,380 rows with 19 columns each. A live graph of unknown shape could expand
much further. Running that against a production database would be indefensible.

**Completeness of paths and bounded live resource use cannot both be guaranteed on an arbitrary
graph.** R15.6.6 therefore withdraws path enumeration entirely. There is **no recursion anywhere
in the file** — no path array, no path text, no depth counter, no outer `LIMIT`, no truncation, no
heuristic preflight, and no reliance on a timeout for correctness.

### What replaced it

| Result set | Content | Row bound |
|---|---|---|
| QUERY 4 — membership **edge inventory** | every `pg_auth_members` row exactly once: member OID and name, granted-role OID and name, grantor OID and name, `admin_option`, `inherit_option`, `set_option`, plus context flags | exactly **E** |
| QUERY 5 — **role reachability** | per (candidate, related role): `membership_exists` (MEMBER), `privileges_inherited_without_set_role` (USAGE), `set_role_permitted` (SET), `inactive_membership_only`, `direct_edge_count`, `distinct_direct_edge_option_shapes` | at most **C × R** |

### Why this is still complete evidence

The question a reviewer must answer is not *by which of the many alternative routes could this role
arrive*, but *what can this role actually do, and which grants produce that*. Those are answered
exactly by the combination of:

- **the complete direct-edge inventory** — every multi-step route is a composition of these edges,
  so no grant that could participate in any route is missing;
- **authoritative `pg_has_role` reachability** — PostgreSQL already accounts for every transitive
  route of any depth. If *any* route of *any* length confers inheritance, USAGE is true; if any
  confers `SET ROLE`, SET is true. An inactive membership is exactly a relationship that no route
  activates;
- **effective privilege checks** (`has_schema_privilege` / `has_table_privilege`) with
  reachability-gated attribution, and direct/self authority reported separately;
- **structured owner and ACL evidence** (Queries 1 and 6).

Critically, **no reachability or privilege fact in this file was ever derived from the enumerated
paths** — they were illustrative detail. An effective privilege therefore cannot disappear because
alternative path rows were removed, and the test suite asserts exactly that against every candidate.

### Exact worst-case row bound

With R = roles, C = candidates, E = `pg_auth_members` rows, A = explicit ACL entries:

```
QUERY 1: 1        QUERY 2: C        QUERY 3: ≤ 9C
QUERY 4: E        QUERY 5: ≤ C·R    QUERY 6: A
TOTAL:   1 + C + 9C + E + C·R + A  =  O(C·R + E + A)
```

No term depends on the number of distinct routes, so graph *density* cannot move the row count —
only the number of roles can. On the 33-role/116-edge fixture the whole diagnostic returns a few
hundred rows instead of 87,380, in well under a second, writing **zero** temporary files.

### Depth is still detectable

Nothing about deep chains became invisible. On the 20-edge chain, reachability reports
`membership_exists`, `privileges_inherited_without_set_role` and `set_role_permitted` all true for
the depth-15, 16, 17 and 20 terminals, with `direct_edge_count = 0` proving the authority is
transitive — and the edge inventory contains each hop exactly once, so a reader can reconstruct the
chain and its length directly. The evidence supports reconstruction; the diagnostic simply does not
pre-expand it. Conflicting alternative routes remain distinguishable: a candidate with both an
inactive direct grant and an active two-step route shows the inactive edge, the active edges, and
reachability saying some route activates it, with `inactive_membership_only = false`.

A conservative transaction-local `statement_timeout` is set as defense in depth. It is not the
protection — the query shapes are.

## 5. Attribution is reachability-gated

The review also found that `via_explicit_acl` could be **true for an ACL the candidate cannot
use**: the holder's membership was `INHERIT FALSE, SET FALSE`, so MEMBER was true while USAGE and
SET were false, direct `SELECT` was denied and `SET ROLE` was denied — yet the ACL was attributed
as if it were a route. An ACL belonging to an unreachable holder is membership evidence, not
access.

Every attribution family is now split by **how the supplying holder is reached**:

| family | usable without `SET ROLE` | reachable via `SET ROLE` | inactive membership |
|---|---|---|---|
| explicit ACL | `explicit_acl_usable_without_set_role` | `explicit_acl_reachable_via_set_role` | `explicit_acl_inactive_membership_evidence` |
| object owner | `via_object_owner_usable_without_set_role` | `via_object_owner_reachable_via_set_role` | `via_object_owner_inactive_membership` |
| predefined `pg_*` role | `via_predefined_role_inherited` | `via_predefined_role_settable` | `via_predefined_role_inactive_membership` |

An effective attribution requires the holder to be the candidate itself, reachable through USAGE,
or reachable through SET. MEMBER alone can only ever set the *inactive* column. The rule is applied
identically to schema ACLs and table ACLs. **`PUBLIC` is attributed independently** —
`via_public_grant` reads the object ACL directly and does not depend on role membership at all.

## 6. Actual object owners versus the pinned contract owner

Owner-route fields previously compared holders against the *pinned contract owner* rather than the
real owner of each protected object. Ownership is now resolved per object:

- schema privileges are attributed against `pg_namespace.nspowner`;
- table privileges are attributed against `pg_class.relowner`;
- `object_owner_role` names the actual owner of the row's object, and
  `object_owner_is_pinned_contract_owner` says whether it matches the pinned owner;
- Query 1 reports `schema_owner`, `table_owner`, `pinned_contract_owner` and three explicit
  conformity flags, so drift between them is visible rather than implied;
- Query 2 reports `is_actual_schema_owner` / `is_actual_table_owner` and separate
  `can_set_role_to_*` / `inherits_from_*` facts for the schema owner, the table owner and the
  pinned owner.

Validated with the schema owner, the table owner and the pinned owner all **different**, and again
with a candidate LOGIN role owning the table itself. Effective access stays visible in every
combination, and inherited, SET-only, and inactive owner memberships are distinguished — each
cross-checked against real `SELECT`/`UPDATE` attempts and real `SET ROLE` outcomes.

## 7. Role validity is not a safety property

`rolvaliduntil` bounds **password authentication only**. An expired LOGIN role still holds every
catalog-defined membership and object privilege it ever had, and can still act through any
authentication method that does not consult the password expiry. **Expiry is therefore not evidence
that an access path is harmless**, and no reachability or attribution fact in the diagnostic depends
on the validity columns — a static test asserts that `rolvaliduntil` never appears near a privilege
predicate. The columns are reported exactly (`rolvaliduntil`, `never_expires`, `currently_valid`,
`expired`) purely as reviewer context. The suite proves the point with an **expired** role that
still holds — and really exercises — an inherited `SELECT`. `rolpassword` is never read or exposed.

## 8. What the diagnostic collects

`28_READ_ONLY_MANAGED_ROLE_DIAGNOSTIC.sql`
(SHA-256 `e869522d253e99601b9f44ded5ea45b578c135b9abeef30612163440994b1304`)
is one explicit `REPEATABLE READ, READ ONLY` transaction containing no mutating SQL, no temporary
objects, no dynamic SQL and no recursion. Candidates are discovered from `pg_roles` — the three
observed names appear nowhere in its executable text. It returns **six** ordered result sets:

| Query | Evidence |
|---|---|
| 1 | Protected-object identity: **actual** schema and table owners, `nspacl`, `relacl`, RLS state, the pinned contract owner, three owner-conformity flags, default-ACL entries scoped to `supabase_migrations`, superuser and total role counts, server version. |
| 2 | Candidate inventory: `LOGIN`, `SUPERUSER`, role-default `INHERIT`, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`, connection limit; exact role validity; the three separated reachability facts (`privileges_usable_without_set_role`, `privileges_via_set_role`, `reaches_protected_objects`); owner exposure against the pinned owner **and** against the actual schema and table owners; role sets as `roles_inherited_from` / `roles_settable_via_set_role` / `roles_inactive_membership_only`, with the predefined `pg_*` roles split the same three ways. |
| 3 | **The core route table** — one row per (candidate, object, privilege) reached by any route, plus rows where only an inactive membership exists. Reachability-gated attribution for explicit ACLs, the actual object owner, and predefined roles (three columns each); `PUBLIC` attributed independently; holder arrays per route kind; `inactive_membership_only` true only in the absence of any active route. Covers schema `USAGE`/`CREATE` and table `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`REFERENCES`/`TRIGGER`. |
| 4 | **Membership edge inventory** — every `pg_auth_members` row exactly once (bound: E): member OID and name, granted-role OID and name, grantor OID and name, `edge_admin_option`, `edge_inherit_option`, `edge_set_option`, plus candidate/predefined/login/superuser/pinned-owner/schema-owner/table-owner context flags. A flat catalog read: no recursion, no traversal, no paths. |
| 5 | **Role reachability** — per (candidate, related role), PostgreSQL's own answer (bound: C·R): `membership_exists`, `privileges_inherited_without_set_role`, `set_role_permitted`, `inactive_membership_only`, `direct_edge_count`, `distinct_direct_edge_option_shapes`, predefined/login/superuser/pinned-owner/schema-owner/table-owner flags, and whether the related role holds any protected privilege. These already account for every transitive route of any depth without enumerating any. |
| 6 | **Structured ACL evidence** — one row per explicit ACL entry on the protected schema and table: object type and identity, grantee OID and name, `grantee_is_public`, grantor OID and name, privilege type, grantability. Empty output means both ACLs are NULL, which is the pinned contract. |

It reads only `pg_roles`, `pg_auth_members`, `pg_namespace`, `pg_class`, `pg_default_acl` and
PostgreSQL's privilege functions. It reads **no application rows**, no migration-history rows, no
`auth` or `storage` schema, no secrets, tokens, credentials, password hashes or customer data, and
no schema other than `supabase_migrations` (the pinned-owner lookup reads `pg_class` metadata for
`public.qhub_manual_review_requests`, never a row from it).

## 9. Which results would remain blocking

The diagnostic produces **evidence, not a verdict**. On review, these outcomes keep the gate shut:

- Any candidate with **write** reach (`INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`) — whether usable
  without `SET ROLE` or reachable via `SET ROLE`. Migration history is an integrity record; a role
  that can rewrite it can forge the applied-migration story.
- Any candidate that can **`SET ROLE` to the pinned owner, an actual object owner, or a
  superuser**, or that **inherits** from any of them — that is full authority over the protected
  objects and the verifier. An inactive membership of an owner is evidence to investigate, not
  access in itself.
- Any candidate reaching the objects through an **explicit ACL entry it can actually use**: the
  pinned contract is `nspacl IS NULL` and `relacl IS NULL`, so such an entry is unexplained
  configuration drift regardless of who holds it. An ACL held by an unreachable role is still
  drift worth explaining, but it is not a candidate access route.
- Any **`PUBLIC`** grant.
- Any candidate whose identity cannot be tied to a documented platform mechanism — including a
  role that merely *looks* managed.
- Any `SET ROLE`-only path that a reviewer cannot attribute to a controlled operator workflow.
- An **expired** role is not thereby safe: expiry bounds password authentication, not authority.

A path could only stop being blocking if a reviewer establishes, from authoritative platform
documentation or the provider directly, (a) exactly which capabilities the role holds here, and
(b) that the identity is genuinely provider-controlled infrastructure with no customer-reachable
credential. That is a human determination requiring evidence this repository does not yet contain.

## 10. If an exception is ever granted

It must be expressed as a **precisely verified capability and identity**, not a name pattern:
narrow, per-role, per-privilege, and re-verified at execution time. Specifically prohibited:

- a broad `pg_`-prefix or `supabase_`-prefix exemption;
- an unconditional role-name whitelist;
- any change that lets a role with write access, owner assumption, or a usable explicit ACL entry
  pass;
- editing the gate to make the current live state green without first explaining it.

Until such an exception is separately reviewed and authorized, the mandatory predicate stands as
implemented, and PRE 25 will continue to return `UNEXPECTED_MIGRATION_HISTORY_STOP`.

## 11. Offline validation harness

The evidence above was produced on a disposable localhost PostgreSQL 16 cluster, never against a
live or remote database. Because PostgreSQL roles are **cluster-scoped**, a fixture role holding
`pg_read_all_data` grants `SELECT` in *every* database of the cluster, including the one a sibling
suite is verifying; parallel Vitest workers therefore contaminated each other. The real-PostgreSQL
suites now serialize through a cross-process directory mutex
(`app/test/helpers/pg-cluster-lock.ts`) that acquires by atomic `mkdir`, records a unique ownership
token, **never reaps a lock on age alone**, and deletes only a lock whose recorded token it can
prove it owns — so a timed-out waiter cannot displace a live holder and a former owner cannot
delete a successor's lock. On timeout it reports the exact lock path and owner metadata for a human
to resolve.

## 12. Status

- Diagnostic 28: corrected for complete path enumeration, reachability-gated attribution, and
  actual-object-owner attribution; offline-validated on disposable localhost PostgreSQL 16 across
  the full 34-case adversarial matrix and all nine protected-object privileges, compared against
  **actual `SET ROLE` success and denial** and actual privilege behaviour before and after the
  switch — and **not executed against any live or remote database**.
- PRE 25 / RECORD 26 / POST 27, the commercial migration, and the statements fixture: **unchanged**
  (hashes re-verified).
- **PRE 25, RECORD 26, POST 27 and diagnostic 28 all remain unauthorized for live execution.** The
  earlier PRE 25 run was a single, separately authorized read-only execution; it conferred no
  standing permission. A future authorization for 28 would cover 28 alone.
- Diagnostic output is **evidence only**. It contains no verdict, approves nothing, and must not
  be treated as clearing any role.
