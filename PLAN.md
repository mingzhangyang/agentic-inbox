# Fix & Improvement Plan

## Priority 1 — Security ✅

### 1.1 Restrict settings mutations ✅
**Files:** `workers/index.ts:103`, `workers/index.ts:128`

`POST /mailboxes` and `PUT /mailboxes/:id` accept `settings: z.record(z.any())`, meaning any authenticated user can inject arbitrary fields — including `agentSystemPrompt` — with no schema enforcement.

**Fix:** Define a `MailboxSettingsSchema` with explicit, typed fields and validate against it in both routes. Reject unknown keys. `agentSystemPrompt` can remain a field but should be a `z.string().max(N)` with a reasonable length cap.

---

### 1.2 Enable auth by default ✅
**File:** `wrangler.jsonc:15`

`ACCESS_AUTH_ENABLED` previously defaulted to `"false"`, making a fresh deployment publicly accessible.

**Fix:** Flip the default to `"true"`. Add a clear comment explaining how to disable it for local development via `.dev.vars`.

---

## Priority 2 — Data Integrity ✅

### 2.1 Complete mailbox deletion ✅
**File:** `workers/index.ts:139`

Deleting a mailbox removes only the R2 metadata key. The Durable Object (SQLite data) and all R2 attachment blobs remain orphaned indefinitely.

**Fix:** On delete:
1. Fetch all email IDs from the mailbox DO.
2. Batch-delete attachment blobs from R2 (`attachments/<emailId>/...`).
3. Only after successful blob deletion, call a `destroy()` method on the `MailboxDO` to drop its SQLite tables or at least mark it deleted.
4. Call the same on the `EmailAgent` DO.
5. Delete the mailbox metadata key last so failed cleanup can be retried.

---

### 2.2 Atomic draft upsert ✅
**File:** `workers/index.ts:218`

Draft update is delete-then-create. If the worker crashes between the two calls, the old draft is lost and no new one exists.

**Fix:** Add a `replaceDraft(id, data)` method to `MailboxDO` that deletes the old draft and inserts the new draft inside one storage transaction. Use it in the draft route and agent tools instead of cross-request delete-then-create patterns.

---

### 2.3 Use email Date header for inbound messages ✅
**File:** `workers/index.ts:399`

Inbound emails are stored with the server receive time, not the sender's `Date:` header. Emails delayed in transit appear as arriving at receive time.

**Fix:** Parse `parsedEmail.date` (PostalMime exposes this). Validate it is a real date and not unreasonably far in the future before using it. Fall back to `new Date()` only if missing or invalid.

---

## Priority 3 — Reliability

### 3.1 Rate limit write paths
**Files:** `workers/index.ts` (drafts, folders, search)

Only the email send path has rate limiting. Draft creation, folder creation, and search are unbounded.

**Fix:** Add per-mailbox rate limiting to:
- `POST /drafts` — prevent draft spam from agents gone rogue
- `POST /folders` — cap folder creation per mailbox
- `GET /search` — limit query frequency to protect DO CPU

Use Cloudflare's [Rate Limiting API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) or a simple counter in the DO.

---

### 3.2 Increase agent step budget for complex flows ✅
**File:** `workers/agent/index.ts:283`, `workers/agent/index.ts:471`

`stopWhen: stepCountIs(5)` previously capped both the interactive agent and the auto-draft flow. A realistic flow (list → get thread → read email → draft) already uses 3–4 steps with no room for error recovery.

**Fix:** Raise to `stepCountIs(10)` for the interactive chat path. Keep a lower cap (e.g. 7) for the auto-draft path to bound cost on inbound email volume.

---

### 3.3 Guard against empty verifyDraft output ✅
**File:** `workers/lib/ai.ts:186`, `workers/agent/index.ts:479`, `workers/lib/tools.ts`

`verifyDraft` returns `""` on AI failure. The caller guards against saving an empty draft via `!sanitizedText`, but if this path is called from other future callers the silent empty-string return is a footgun.

**Fix:** Have `verifyDraft` return `string | null` — `null` on failure, cleaned text or original on success. Update call sites to handle `null` explicitly.

---

## Priority 4 — Code Health

### 4.1 Type the Durable Object stub properly
**File:** `workers/index.ts:155–156`

`(stub as any).getThreadedEmails` and `(stub as any).countThreadedEmails` bypass TypeScript. Similar `as any` casts appear in the DO route and agent code.

**Fix:** Extend the `MailboxDO` stub interface (or use RPC types if available) to include all methods called via `as any`. This catches method renames and signature changes at compile time.

---

### 4.2 Type the EmailAgent env binding
**File:** `workers/agent/index.ts:275`

`AIChatAgent<any>` is used because the `SEND_EMAIL` binding shape conflicts with the generic constraint.

**Fix:** Create a typed `AgentEnv` interface that satisfies `AIChatAgent`'s constraint and includes the `SEND_EMAIL` binding. Cast at the boundary rather than erasing the type entirely.

---

### 4.3 Subject-based thread grouping false positives
**File:** `workers/durableObject/index.ts` (`findThreadBySubject`)

Subject matching groups unrelated emails that share a subject line (e.g. "Hello", "Follow up").

**Fix:** Add a time window constraint — only match threads with a message in the last N days (e.g. 30). Optionally also require the sender domain to match.

---

## Priority 5 — UX / Operational

### 5.1 Surface email Date header in UI
Tied to fix 2.3. Once inbound emails store the correct `Date:` header value, the email list sort order and timestamps will reflect actual send time rather than arrival time.

---

### 5.2 Warn when mailbox deletion is incomplete ✅
Superseded by fix 2.1: mailbox deletion now purges R2 attachment blobs, mailbox DO storage, and agent DO storage before removing mailbox metadata.

---

### 5.3 Document agent step budget and cost implications ✅
The auto-draft path fires on inbound email when `autoDraftEnabled` is not `false` and can call Workers AI for injection scanning, draft generation, and draft verification. At volume this becomes significant.

**Fix:** Add an `autoDraftEnabled` boolean to the mailbox settings schema and gate the auto-draft trigger on it so operators can disable auto-draft per mailbox without editing the system prompt.
