# safe-deps — Dependency Policy for Orgs Adopting Coding Agents

**Status:** spec (scope frozen 2026-09-14)
**Owner:** Dominic Serrano
**Build window:** Mon 9/14 – Fri 9/18 (week 1 of the build plan)
**Sibling project:** [safe-migrate](https://github.com/dmserrano/safe-migrate)

---

## Problem

An org rolls out coding agents. Pull requests that add or bump dependencies now arrive
faster than anyone reviews them, and two risks grow with adoption:

1. **Compromised releases.** A legitimate package ships a malicious version (the 2025 npm
   chalk/debug and Shai-Hulud incidents). Advisory databases learn about it *after* it has
   been installable for hours.
2. **Hallucinated package names ("slopsquatting").** A model invents a plausible package
   name, an attacker registers it, and an agent adds it.

Per-repo scanners already exist and work. What an org with 20 repos (or a consultancy with
20 client orgs) lacks is the **governance layer**: one policy, exceptions that a named
person approves and that expire, stricter rules for agent-authored changes, and an audit
trail someone can query.

## What this is

A GitHub Action plus a small audit service that a client org installs to:

- block merges that add known-vulnerable, malicious, or too-new dependencies
- apply stricter policy when the PR was written by an agent
- grant exceptions through PRs approved by the security team, scoped to one advisory, with an expiry
- record every decision to an audit log the org owns
- explain each block on the PR, and propose the fix when one exists

## What this is not

- **Not a scanner.** `osv-scanner` does detection. This wraps it.
- **Not a product or a replacement for Socket / Snyk / Sonatype.** It is a reference
  implementation of the layer those vendors sell, built from free parts.
- **Not an install-time tool.** It gates merges, not `npm install` on a laptop.
- **Not multi-tenant SaaS.** Each client deploys their own audit service.

---

## Build vs. buy

| Need | Free tools | Paid tools | safe-deps |
|---|---|---|---|
| Detect known vulns in lockfiles | `osv-scanner`, `dependency-review-action` | all | **uses** `osv-scanner` |
| PR check + scheduled re-scan | `osv-scanner` reusable workflows | all | **uses** |
| Per-repo exceptions with reason + expiry | `osv-scanner.toml` `IgnoredVulns` | all | **uses** (generated) |
| Fix-version PRs | Dependabot | all | agent adds explanation + exception draft |
| Min release age | Renovate / pnpm (delays upgrades, not enforced at merge) | Socket | **builds**: enforced at merge |
| **One org policy across repos** | — | Snyk, Sonatype, Socket | **builds** |
| **Exceptions approved by a named team, matched across advisory aliases** | — | Sonatype waivers | **builds** |
| **Malicious advisories can never be waived** | — | varies | **builds** |
| **Stricter policy for agent-authored PRs** | — | — | **builds** |
| **Org-owned audit log** | — | all (vendor-hosted) | **builds** |

**Evidence the gap is real but narrow:** [google/osv-scanner#2205](https://github.com/google/osv-scanner/issues/2205)
— a team needed exceptions split by approver (engineering manager signs off on production
ignores). Maintainers closed it as not planned: *do it with an external script.* safe-deps
is that script, done properly.

**Why `osv-scanner` over `dependency-review-action`:** client repos are mostly private, and
dependency review on private repos requires a paid GitHub security license.

---

## Design principles

1. **Deterministic decisions.** Policy decides pass/block. The agent never does.
2. **Gate where it can't be skipped.** Required status check + ruleset; no git hooks.
3. **Fail closed on scanning, fail open on logging.** If the scan can't run, the check fails.
   If the audit service is down, the decision stands and the event goes to the job summary.
4. **Exceptions are code.** Approval is a PR review; history is git.
5. **No person-bound credentials.** GitHub App for cross-repo reads, OIDC for the audit service.
6. **Configure before building.** Anything a free tool already does is configured, not rewritten.

---

## Policy model

Lives in the client's policy repo (default name: `security-policy`).

```yaml
# policy.yaml
version: 1
ecosystems: [npm]

block:
  severity: critical          # critical | high | medium | low
  unknown_severity: warn      # block | warn
  malicious: always           # not configurable; documented here for readers

release_age:
  min_days: 3

agent_authored:
  detect:
    authors: []               # bot logins that count as agents (configured per org)
    labels: [agent-authored]
  release_age:
    min_days: 7
  new_dependency_requires_review_from: security   # team slug

repos:                        # overrides may only tighten
  payments-api:
    block:
      severity: high
```

```yaml
# exceptions.yaml — changes require CODEOWNERS approval from the security team
- id: CVE-2021-23337          # any alias works; matched across OSV aliases
  repos: [legacy-admin]       # optional; omit for org-wide
  reason: "No fixed version compatible with Node 14; removal tracked in LEG-412"
  expires: 2026-10-15         # required
```

### Rules, in evaluation order

| # | Rule | Result | Waivable? |
|---|---|---|---|
| 1 | Scan failed / OSV unreachable | fail | no (break-glass: disable check in ruleset, logged by GitHub) |
| 2 | Advisory ID starts with `MAL-` (or any alias does) | block | **no** |
| 3 | Version published < `release_age.min_days` ago (agent PR: `agent_authored.release_age`) | block | yes, by package@version exception |
| 4 | Severity ≥ threshold (after repo tightening) | block | yes, by advisory ID |
| 5 | Severity unknown | per `unknown_severity` | yes, by advisory ID |
| 6 | Agent PR adds a new dependency (not a bump) | block until approved review from the named team | no exception; the review *is* the approval |

**Override rule:** a repo override that loosens any value is rejected at load time with an error.

---

## Components

```
safe-deps/
  action/           # GitHub Action (TypeScript). The gate.
  service/          # Audit intake API (TypeScript) + Postgres migrations (plain SQL)
  agent/            # gh aw workflow: explain, bump PR, exception draft
  examples/policy/  # policy.yaml, exceptions.yaml, CODEOWNERS
  docs/             # install guide, build-vs-buy, limitations
```

Demo org (separate): `security-policy` repo + three scenario repos.

### 1. Action (`action/`)

1. Get a GitHub App installation token (`actions/create-github-app-token`); read `policy.yaml` + `exceptions.yaml` from the policy repo.
2. Validate policy; reject loosening overrides.
3. Expand each exception ID to its aliases via `GET https://api.osv.dev/v1/vulns/{id}`. Refuse any exception whose ID or alias is `MAL-`.
4. Generate `osv-scanner.toml` with `IgnoredVulns` (`id`, `ignoreUntil`, `reason`) for this repo.
5. Run `osv-scanner --format json` on the lockfile. Non-zero from a scan *error* → rule 1.
6. Post-check: assert no `MAL-` finding was suppressed.
7. Release age: for each added/changed package@version, read publish time from `https://registry.npmjs.org/<pkg>` (`time` field).
8. Agent detection: PR author in `detect.authors` or label present. If agent-authored and the diff adds a new top-level dependency, require an approving review from a member of the named team.
9. Decide. Write the job summary (always). POST events to the audit service with an OIDC token (never blocks the decision).
10. Exit non-zero on block.

**Triggers:** `pull_request` (required check), `schedule` nightly on default branch (opens/updates one issue per finding instead of failing a PR), `pull_request_review` (re-evaluate rule 6).

**Distribution:** tagged releases; install docs pin by commit SHA.

### 2. Audit service (`service/`)

- `POST /events` — batch of decision events.
- **Auth:** verify the Actions OIDC JWT against GitHub's JWKS; check `iss`, `exp`, `aud`, and `repository_owner_id` ∈ allowlist (numeric ID, not org name).
- **Deploy:** one minimal hosted instance for the demo org (Fly.io or Render + managed Postgres — pick Tuesday). Allowlist and `aud` via env config.
- **No UI.** Reporting is a saved SQL file.

**Table (starting point — refine by hand):**

```sql
CREATE TABLE decision_events (
  id              bigserial PRIMARY KEY,
  owner_id        bigint      NOT NULL,   -- repository_owner_id from OIDC
  repo            text        NOT NULL,
  pr_number       int,                    -- null for scheduled scans
  commit_sha      text        NOT NULL,
  run_id          bigint      NOT NULL,
  trigger         text        NOT NULL,   -- pull_request | schedule | review
  actor_type      text        NOT NULL,   -- human | agent
  outcome         text        NOT NULL,   -- pass | warn | block | exception_applied | scan_error
  rule            text,                   -- malicious | release_age | severity | unknown_severity | agent_new_dep
  ecosystem       text,
  package         text,
  version         text,
  advisory_id     text,                   -- ID as reported by the scanner
  exception_id    text,                   -- ID as written in exceptions.yaml, if one applied
  created_at      timestamptz NOT NULL DEFAULT now()
);
```

**Breadth hook — hands-on, not delegated:** the query is

```sql
-- Blocks by repo, last 30 days, for one org
SELECT repo, rule, count(*)
FROM decision_events
WHERE owner_id = $1 AND outcome = 'block' AND created_at > now() - interval '30 days'
GROUP BY repo, rule
ORDER BY count(*) DESC;
```

Seed ≥100k rows, run `EXPLAIN (ANALYZE, BUFFERS)` before and after your index, and commit
both plans to `docs/explain.md` with a paragraph on why the planner chose what it chose.
Also: `agent vs. human block rate` — one more saved query, same file.

### 3. Agent (`agent/`)

`gh aw` workflow, triggered when the safe-deps check fails on a PR. Read-only; writes only through safe outputs.

| Finding | Agent does |
|---|---|
| `MAL-` | One comment: what the advisory is, "remove this dependency." Nothing else. |
| Vuln with a fixed version | Comment with plain-language explanation + open a bump PR to the nearest fixed version. |
| Vuln with no fix | Comment + open a **draft** PR to the policy repo adding an exception entry (reason blank, expiry 30 days). Never approves. |
| Release age | Comment: when the version becomes eligible, and the previous version to pin instead. |
| Agent new dependency | Comment tagging the security team with what the package is, its age, and weekly downloads. |

---

## Eval criteria — the demo must pass these

Each scenario is a PR in a demo-org repo. Pass = the observed result matches, and the audit
row exists.

| # | Scenario | Expected |
|---|---|---|
| 1 | Human PR adds a package version with a known critical advisory that has a fixed version | Check fails (rule 4). Agent comments + opens bump PR. Bump PR passes. |
| 2 | PR's **lockfile** references a version with a `MAL-` advisory *(lockfile only — never `npm install` in this repo)* | Check fails (rule 2). Exception PR for that ID is rejected by the action. Agent comments "remove" only. |
| 3 | **(protected)** Critical advisory with no usable fix → exception merged with `expires` = tomorrow | Check passes, `exception_applied` row written with the alias the exception used. Next nightly scan after expiry opens an issue on main. |
| 4 | Agent-labeled PR adds a brand-new dependency published 5 days ago | Check fails (rule 3 at 7 days *and* rule 6). Same PR from a human passes rule 3 at 3 days. |
| 5 | Repo override tries `severity: low → critical` loosening | Action fails at policy load with a clear error. |
| 6 | Audit service stopped | Scenario 1 still blocks; event in job summary; no crash. |

Unit tests cover: policy loading + tightening, alias expansion, `MAL-` refusal, release-age
math, agent detection. Scenarios are the integration test.

---

## Week plan

| Day | Build | Done when |
|---|---|---|
| **Mon 9/14** | This spec. Create repo + demo org. | Spec committed. |
| **Tue 9/15** | Policy loader + tightening check, exception generator + alias expansion, action running `osv-scanner` locally | Scenarios 1, 2, 5 pass locally against fixture lockfiles |
| **Wed 9/16** | Demo org wiring: GitHub App, ruleset + required check, CODEOWNERS. Release age + agent rules. Nightly schedule. | Scenarios 1–5 pass in GitHub |
| **Thu 9/17** | Audit service: OIDC verify **by hand**, Postgres schema, deploy. Seed + `EXPLAIN` **by hand**. `gh aw` agent. | Scenario 6 passes; `docs/explain.md` committed |
| **Fri 9/18** | README with limitations, install doc, build-vs-buy doc. Oral defense via `interview-drill`. Article draft. | Tagged `v0.1.0` |

**Cut order if behind** (last cut first): exception-draft PR → release-age agent comment →
bump PR → hosted deploy (fall back to local service + tunnel for the demo recording).
**Never cut:** scenario 3, the OIDC check, the `EXPLAIN` work.

**Hands-on (not delegated):** GitHub App token flow, OIDC verification, the index + `EXPLAIN`.
Everything else may be delegated to an agent, and must be defensible on Friday.

---

## Friday defense — must answer without notes

1. Why the block decision is deterministic and where the agent is allowed to act.
2. How a GitHub App installation token is issued, and why it beats a PAT.
3. Which OIDC claims the service checks and why `repository_owner_id` instead of the org name.
4. Why an exception is scoped to an advisory ID, and what alias matching prevents.
5. Why a severity threshold alone lets a compromised package through.
6. Why a `MAL-` entry can never be waived.
7. The `EXPLAIN` plan: what changed with the index and why.
8. Build vs. buy: what you didn't build, and what you'd tell a client who already pays for Snyk.
9. **Limitation you measured** (for the article): e.g. how long the release-age rule would have held a real 2025 compromised version vs. when its `MAL-` entry appeared.

---

## Not this week (→ README "what's next")

- Deploy-time gate before prod
- Ecosystems beyond npm
- Additional advisory sources behind an `AdvisorySource` interface (e.g. Socket) — interface stubbed, OSV only
- MCP server as an advisory-only client of the same policy, for agents at coding time
- Any UI
- Multi-tenant hosted service

## Open questions (resolve Tuesday morning, before code)

1. **Agent PR detection:** which bot logins do current coding agents (Copilot coding agent, Claude, Codex) actually open PRs under? Verify, don't assume; the label fallback covers the gap.
2. **Rule 6 enforcement:** reading team membership needs the App to have `members: read` on the org. Confirm the permission, or fall back to CODEOWNERS on lockfiles for agent branches.
3. **Does `osv-scanner`'s `IgnoredVulns` already match aliases?** If yes, alias expansion is still needed for the `MAL-` refusal but not for suppression.
4. **Scenario 2 fixture:** pick a real `MAL-` npm entry whose package has been removed from the registry, so the lockfile reference is inert.
