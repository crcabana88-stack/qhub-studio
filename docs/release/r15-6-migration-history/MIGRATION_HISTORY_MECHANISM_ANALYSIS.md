# R15.6 Migration-History Reconciliation — Offline Mechanism Analysis

Strictly offline. Produced at approved commit `5a88cbf54b4c3cdf7ce17d57b46c495ff8861b44` with no
live system contact of any kind. Every claim below is derived from committed repository content or
from the locally installed, pinned CLI binary — nothing was fetched.

## 1. The migration whose history entry is being reconciled

| Item | Value |
|---|---|
| Path | `supabase/migrations/20260729_commercial_launch_foundation.sql` |
| Filename | `20260729_commercial_launch_foundation.sql` |
| Byte length | 125,186 |
| SHA-256 | `1509eb59056764b0b6500aa8bfbb2df65eb330a1ff363758bff0e4797427a755` |
| Migration version | `20260729` |
| Migration name | `commercial_launch_foundation` |
| Expected history representation | one complete row in `supabase_migrations.schema_migrations(version, statements, name)`: `version='20260729'`, `name='commercial_launch_foundation'`, `statements` = the exact 89-element CLI-derived `text[]` payload (124,959 bytes, canonical digest `7b28ccf3ba7cae3e29c17bc5c3be60b6`). The statements are INSERT data only and are never executed. There is no two-field or NULL-statements insert; the only permitted durable mutation is one explicit three-column INSERT, and an already-exact state is a no-op. |

Version and name are not guessed: they are the output of the pinned CLI's own filename parser
(§2) applied to the committed filename.

## 2. The authoritative migration-history contract (extracted from the installed CLI)

The project's only established history mechanism is the Supabase CLI pinned by every reviewed
runbook (`npx --yes supabase@2.110.0`, in `docs/release/r15-2-verifier-patch/`,
`r15-3-body-restoration/`, `r15-5-runtime-verifier/`, `r15-6-runtime-verifier/`). That exact
version is present offline in the local npx cache
(`npm-cache/_npx/7960735060baecd3/node_modules/supabase`, package.json version `2.110.0`;
platform binary `@supabase/cli-windows-x64/bin/supabase.exe`, package version `2.110.0`, SHA-256
`14814afa6fe59081eb9f24709fc077226bf89bc25cf77ee3bcb19565f3ef8899`). The following was extracted **verbatim**
from that binary; no network access and no execution against any project occurred.

Filename parsing:

```
^([0-9]+)_(.*)\.sql$          -> (version, name)
```

History table DDL (the CLI's own creation/upgrade sequence):

```sql
CREATE SCHEMA IF NOT EXISTS supabase_migrations
CREATE TABLE IF NOT EXISTS supabase_migrations.schema_migrations (version text NOT NULL PRIMARY KEY)
ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN IF NOT EXISTS statements text[]
ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN IF NOT EXISTS name text
```

Read paths:

```sql
SELECT version, coalesce(name, '') as name, statements FROM supabase_migrations.schema_migrations
SELECT version FROM supabase_migrations.schema_migrations ORDER BY version
```

Write paths:

```sql
-- upsert (used by `migration repair --status applied` — see below)
INSERT INTO supabase_migrations.schema_migrations(version, name, statements)
VALUES($1, $2, $3)
ON CONFLICT (version) DO UPDATE SET name = EXCLUDED.name, statements = EXCLUDED.statements
-- plain insert (other flows)
INSERT INTO supabase_migrations.schema_migrations(version, name, statements) VALUES($1, $2, $3)
-- `migration repair --status reverted`
DELETE FROM supabase_migrations.schema_migrations WHERE version = ANY($1)
-- reset path (never authorized here)
TRUNCATE supabase_migrations.schema_migrations
```

The repair implementation itself (minified, quoted verbatim from the binary; `Pm` is the upsert
above, `baH` the delete, `haH` the truncate):

```
if(I==="applied")for(let N of D){let W=yield*paH(A,L,$,N);
if(Z.isNone(W))return yield*T.fail(new OMH({message:`glob supabase/migrations/${N}_*.sql: file does not exist`}));
M.push(yield*caH(A,L,W.value))}
if(yield*T.gen(function*(){if(yield*H.exec("BEGIN"),_)yield*H.exec(haH);
if(I==="applied")for(let N of M)yield*H.query(Pm,[N.version,N.name,N.statements]);
else if(!_)yield*H.query(baH,[D]);yield*H.exec("COMMIT")})
.pipe(T.tapError(()=>H.exec("ROLLBACK").pipe(T.ignore)), ...
```

So `supabase migration repair --status applied 20260729` would: (1) require the local file
`supabase/migrations/20260729_*.sql` (exactly one exists), (2) parse it into
`(version='20260729', name='commercial_launch_foundation', statements=<CLI statement split>)`,
(3) run the **upsert** inside `BEGIN … COMMIT` with `ROLLBACK` on error.

## 3. Mechanism comparison

| Criterion | CLI `migration repair --status applied` | Narrow SQL transaction (chosen) |
|---|---|---|
| Exact mutation scope | one upsert row (proven) — but may **UPDATE** an existing row | at most one explicit three-column INSERT into `supabase_migrations.schema_migrations(version, statements, name)` carrying the exact CLI-derived statements payload; can never update or delete; already-exact state is a no-op |
| Duplicate/conflict protection | **none** — `ON CONFLICT (version) DO UPDATE` silently overwrites a conflicting name/statements | refuses: wrong-name row, NULL-name (partial/legacy) row, same name under another version, any version newer than `20260729` |
| Verifier-READY gating | impossible | mandatory in-transaction gate: verifier digest + authority + `ready=true`, exact version, `failed=[]` |
| Transaction behavior | BEGIN/COMMIT with rollback (proven) | explicit BEGIN/COMMIT; every gate raises before the insert; any exception rolls back everything |
| Auditability | prints `Repaired migration history: [20260729] => applied`; inserted values depend on the operator's local checkout at run time | the artifact is committed, hash-pinned, reviewed; the final SELECT returns the exact action taken and the resulting row |
| Metadata preservation | records `statements` (CLI statement split of the local file) | records the **identical** CLI-derived statements array, fixed at review time and digest-gated (see §4 — corrected) |
| Wrong-project protection | linked project ref only | runs only inside the project's SQL Editor per runbook, and the in-transaction gates require this exact database's verifier digest + READY state — a different project fails closed |
| Offline provability | behavior proven from the installed binary, but execution needs network + link + credentials, and `npx --yes` may re-contact the registry | fully self-contained SQL |
| Established live-mutation channel | never used live in this project so far | **every** prior live mutation in this release went through hash-pinned SQL Editor artifacts with PRE/PATCH/POST gates |

**Decision: the narrow SQL transaction (26).** The CLI cannot satisfy two hard requirements of
this package — refusing conflicting/ambiguous history state and refusing execution when the
commercial verifier is not READY — because its only applied-path write is an unconditional upsert.
The SQL artifact produces the identical single-row outcome using the CLI's own derived values and
table contract, adds every refusal the CLI lacks, and travels the project's established, reviewed
live-mutation channel.

## 4. The `statements` field — the exact CLI array, derived offline (CORRECTED)

> The first revision of this package recorded `statements = NULL`. The independent review
> rejected that (P2-1: NULL is incompatible with reliable CLI fetch/reconstruction), and an
> authorized local-PostgreSQL validation environment made the exact derivation possible. The
> corrected package records the complete CLI-compatible row.

The exact array was derived by invoking the **installed pinned binary by explicit local path**
(never `npx`, no registry contact, no live project) against an isolated localhost-only scratch
PostgreSQL 16 server:

```
supabase.exe migration repair --status applied 20260729
  --db-url postgresql://…@127.0.0.1:54329/<scratch-db>?sslmode=disable
```

run from a scratch project directory containing a byte-exact copy of the committed migration.
The CLI's own parser wrote the row; the array was then read back with `psql`.

**Derivation record (all against PostgreSQL 16.4, localhost only):**

| Proof | Result |
|---|---|
| Run 1 (scratch db 1) | cardinality **89**, total statement bytes **124,959**, canonical digest **`7b28ccf3ba7cae3e29c17bc5c3be60b6`** |
| Run 2 (scratch db 2, independent) | identical |
| Run 3 (db 1, row deleted, re-repaired) | identical |
| Canonical digest definition | `md5( concat over elements of octet_length(elem) ‖ ':' ‖ elem, in order )` — length-prefixed, delimiter-unambiguous; reproduced independently in Node.js over the fixture with the identical value |
| Verbatim containment | all 89 statements are verbatim substrings of the committed migration, in order (residual 227 bytes = inter-statement whitespace/comments the parser strips) |
| CLI fetch reconstruction | `supabase.exe migration fetch --db-url …` regenerated `supabase/migrations/20260729_commercial_launch_foundation.sql` from the stored row — non-empty, correct CLI-derived filename, 125,137 bytes, md5 `bd2bf7144c7f675bf403672765c342ca`, containing all 89 statements verbatim in order |

The array is committed as `app/test/fixtures/r8-20260729-cli-statements.json`
(SHA-256 `d2e85b8c5f68735ff9cf817a5cdcfb9751a980f913ebff1c5886bab56ef9999d`) and embedded in `26`
as single-line base64 **INSERT data**: decoded and digest-gated inside the transaction, never
interpreted, never executed, no dynamic SQL or `EXECUTE` path anywhere in the artifact. Base64 is
line-ending-inert, so a CRLF-normalizing transfer channel cannot corrupt the payload — and the
digest gate would refuse it if anything else did.

An existing target row with NULL, incomplete, or different statements is a **STOP**, never an
update.

## 4b. Concurrency design (CORRECTED — review P1-1)

`26` acquires `LOCK TABLE supabase_migrations.schema_migrations IN SHARE ROW EXCLUSIVE MODE`
inside its single explicit transaction **before trusting any database state**, and holds it
through COMMIT. Per the PostgreSQL conflict matrix, SHARE ROW EXCLUSIVE conflicts with ROW
EXCLUSIVE (every INSERT/UPDATE/DELETE writer — including the CLI's own repair upsert) and with
itself (two concurrent `26` runs serialize), while permitting plain readers. It is the
least-permissive table lock with both properties (SHARE does not self-conflict for this purpose:
two SHARE holders could each validate and then deadlock or interleave on upgrade; EXCLUSIVE
additionally blocks ROW SHARE readers unnecessarily). Advisory locks were rejected because
noncooperating writers do not honor them. Every gate — verifier authority, product readiness,
table contract, conflicts — runs **after** the lock, so nothing can change between validation and
the INSERT. Proven with two independent psql sessions against real PostgreSQL 16
(`app/test/commercial-r15-6-history-concurrency.test.ts`): a second SRE lock and a concurrent
INSERT both block; conflicts committed while `26` waits are refused by the post-lock recheck
(wrong-name, same-name-other-version, newer-version, malformed-version races); of two concurrent
runs exactly one records and the other no-ops. Isolation is explicitly READ COMMITTED so
post-lock reads observe the newest committed state.

## 4c. The migration-history privilege contract (CORRECTED — second review P1-1)

The pinned privilege state is derived from the same authoritative evidence as the table shape:
the CLI's own extracted DDL contains **no GRANT of any kind** and runs as the connecting role
(the contract owner), and the platform's default-privilege statements are scoped to schema
`public` — they never touch `supabase_migrations`. PostgreSQL grants PUBLIC nothing on a new
non-public schema or a new table. The pinned deployment state is therefore:

| Item | Pinned value |
|---|---|
| `supabase_migrations` schema owner | the contract owner (owner of the migration-created tables) |
| `schema_migrations` table owner | the contract owner |
| `pg_namespace.nspacl` | **NULL** — zero explicit entries |
| `pg_class.relacl` | **NULL** — zero explicit entries |
| Effective schema USAGE/CREATE | owner and superusers only |
| Effective table SELECT/INSERT/UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER | owner and superusers only |
| anon / authenticated / service_role | **no privilege of any kind, direct or inherited** |

Because the pinned explicit ACLs are NULL, *any* materialized entry — an extra grantee, a
redundant owner self-grant, a different grantor, a grantable bit, a PUBLIC grant — changes
`nspacl`/`relacl` away from NULL and fails the cardinality-zero contract; there is no NULL
ambiguity because NULL is asserted affirmatively (`acl IS NULL` must be TRUE, NULL-safely).
Effective privileges are enumerated per `pg_roles` role with
`has_schema_privilege`/`has_table_privilege`, which follow role membership, so
membership-derived access fails closed too. All three artifacts bind this contract into their
verdicts: PRE 25 STOPs, RECORD 26 raises `unexpected_migration_history_privilege` **after** the
SHARE ROW EXCLUSIVE lock and before any durable DML — there is no pre-lock authorization
decision, and the post-lock READ COMMITTED recheck sees every grant committed up to lock
acquisition (GRANT itself does not conflict with SHARE ROW EXCLUSIVE — empirically verified — so
a grant landing after the recheck is possible; it cannot alter the recorded row and is refused by
the mandatory, separately authorized POST 27 in its own snapshot). POST 27 returns
NOT_RECONCILED on any privilege drift. The verifier metadata contract was simultaneously
completed with `proparallel = 'u'` and `proisstrict = false`, pinned from the approved verifier
artifact; both feed the same verdicts and gates.

## 5. What could not be proven offline, and how the package closes it

The live rows of `supabase_migrations.schema_migrations` (which prior versions are recorded and
under what names) are not recorded anywhere in the repository. The package does **not** assume
them: PRE 25 discovers and displays them read-only, gates only on the `20260729`-relevant
conditions, and both 26 and POST 27 re-verify everything in their own snapshots. Every unproven
aspect fails closed at execution time; nothing depends on an offline guess.

## 6. Conflict-case inventory and disposition

| Case | PRE 25 | PATCH 26 | POST 27 |
|---|---|---|---|
| Version already recorded correctly | `ALREADY_RECORDED_EXACTLY` | clean no-op, same token | `MIGRATION_20260729_HISTORY_RECONCILED` |
| Version under a different name | STOP | raises `migration_history_conflict` | NOT_RECONCILED |
| Version with NULL name (partial/legacy) | STOP | raises `migration_history_conflict` | NOT_RECONCILED |
| Same name under a different version | STOP | raises `migration_history_conflict` | NOT_RECONCILED |
| Duplicate version rows | impossible under the verified `(version)` PK; PK itself is verified, absence is a shape STOP | same | same |
| Any version newer than `20260729` | STOP | raises `migration_history_conflict` | NOT_RECONCILED |
| History table missing / shape drift / unexpected mandatory column | STOP (never a SQL error) | raises `unexpected_migration_history_shape` | NOT_RECONCILED |
| Verifier not READY / body or authority drift | STOP | raises `unexpected_runtime_verifier_*` / `migration_history_product_not_ready` | NOT_RECONCILED |
| Repository/artifact hash drift | runbook step 0 blocks before any live contact | same | same |
| Wrong target project | runbook project-ref confirmation + this database's verifier gates fail closed | same | same |
