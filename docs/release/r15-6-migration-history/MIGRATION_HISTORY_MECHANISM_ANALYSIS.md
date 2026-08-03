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
| Expected history representation | one row `(version='20260729', name='commercial_launch_foundation')` in `supabase_migrations.schema_migrations` |

Version and name are not guessed: they are the output of the pinned CLI's own filename parser
(§2) applied to the committed filename.

## 2. The authoritative migration-history contract (extracted from the installed CLI)

The project's only established history mechanism is the Supabase CLI pinned by every reviewed
runbook (`npx --yes supabase@2.110.0`, in `docs/release/r15-2-verifier-patch/`,
`r15-3-body-restoration/`, `r15-5-runtime-verifier/`, `r15-6-runtime-verifier/`). That exact
version is present offline in the local npx cache
(`npm-cache/_npx/7960735060baecd3/node_modules/supabase`, package.json version `2.110.0`, Go/JS
binary `@supabase/cli-windows-x64/bin/supabase.exe`). The following was extracted **verbatim**
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
| Exact mutation scope | one upsert row (proven) — but may **UPDATE** an existing row | at most one INSERT of `(version, name)`; can never update or delete |
| Duplicate/conflict protection | **none** — `ON CONFLICT (version) DO UPDATE` silently overwrites a conflicting name/statements | refuses: wrong-name row, NULL-name (partial/legacy) row, same name under another version, any version newer than `20260729` |
| Verifier-READY gating | impossible | mandatory in-transaction gate: verifier digest + authority + `ready=true`, exact version, `failed=[]` |
| Transaction behavior | BEGIN/COMMIT with rollback (proven) | explicit BEGIN/COMMIT; every gate raises before the insert; any exception rolls back everything |
| Auditability | prints `Repaired migration history: [20260729] => applied`; inserted values depend on the operator's local checkout at run time | the artifact is committed, hash-pinned, reviewed; the final SELECT returns the exact action taken and the resulting row |
| Metadata preservation | records `statements` (CLI statement split of the local file) | records `statements = NULL` (see §4) |
| Wrong-project protection | linked project ref only | runs only inside the project's SQL Editor per runbook, and the in-transaction gates require this exact database's verifier digest + READY state — a different project fails closed |
| Offline provability | behavior proven from the installed binary, but execution needs network + link + credentials, and `npx --yes` may re-contact the registry | fully self-contained SQL |
| Established live-mutation channel | never used live in this project so far | **every** prior live mutation in this release went through hash-pinned SQL Editor artifacts with PRE/PATCH/POST gates |

**Decision: the narrow SQL transaction (26).** The CLI cannot satisfy two hard requirements of
this package — refusing conflicting/ambiguous history state and refusing execution when the
commercial verifier is not READY — because its only applied-path write is an unconditional upsert.
The SQL artifact produces the identical single-row outcome using the CLI's own derived values and
table contract, adds every refusal the CLI lacks, and travels the project's established, reviewed
live-mutation channel.

## 4. The `statements` field — explicitly NULL, not guessed

The CLI would record `statements` as its own parser's statement split of the 125,186-byte
migration. That split is implemented inside the minified binary and is **not reproducible offline
with byte certainty**; fabricating an approximation would violate the derive-don't-guess rule.
The chosen mutation therefore records `statements = NULL`, which is safe and honest because:

- the column is nullable in the CLI's own DDL (added via `ADD COLUMN IF NOT EXISTS`);
- the CLI's version-comparison paths (`migration list`, `db push` preflight) key on `version`
  (`SELECT version FROM … ORDER BY version`);
- the CLI's read path tolerates missing metadata (`coalesce(name, '')`), and the R15.2 runbook
  already documents blank remote metadata as a known, tolerated condition in this project;
- the row can later be upgraded to carry `statements` by an explicitly authorized CLI run — that
  decision is deliberately left to a future human gate, not smuggled into this one.

`name` **is** recorded, exactly, because it is fully derivable (§2) and because leaving it NULL
would create precisely the "partial/legacy metadata" state this package treats as a STOP.

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
