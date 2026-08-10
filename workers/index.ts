// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { type Context, Hono } from "hono";
import { cors } from "hono/cors";
import PostalMime from "postal-mime";
import { z } from "zod";
import { deleteAttachmentObjects, storeAttachments, type StoredAttachment } from "./lib/attachments";
import {
	validateSender,
	SenderValidationError,
	generateMessageId,
	listMailboxes,
} from "./lib/email-helpers";
import { MAX_BODY_LENGTH, SendEmailRequestSchema, MailboxSettingsSchema } from "./lib/schemas";
import { handleReplyEmail, handleForwardEmail } from "./routes/reply-forward";
import type { Env } from "./types";
import { requireMailbox, type MailboxContext } from "./lib/mailbox";
import { enqueueOutboundEmail, hashPayload } from "./lib/outbox";

type AppContext = Context<MailboxContext>;

// -- Request body schemas (kept for validation) ---------------------

const CreateMailboxBody = z.object({
	email: z.string().email(),
	name: z.string().min(1).max(100),
	settings: MailboxSettingsSchema.optional(),
}).strict();

const DraftBody = z.object({
	to: z.string().max(2_000).optional(),
	cc: z.string().max(2_000).optional(),
	bcc: z.string().max(2_000).optional(),
	subject: z.string().max(200).optional(),
	body: z.string().max(MAX_BODY_LENGTH),
	in_reply_to: z.string().optional(),
	thread_id: z.string().optional(),
	draft_id: z.string().max(200).optional(),
}).strict();

const FolderBody = z.object({ name: z.string().min(1).max(100) }).strict();
const EmailUpdateBody = z.object({ read: z.boolean().optional(), starred: z.boolean().optional() }).strict();
const MoveEmailBody = z.object({ folderId: z.string().min(1).max(100) }).strict();

// -- Helpers --------------------------------------------------------

function slugify(text: string) { // can return "" for non-alphanumeric input
	return text.toString().toLowerCase()
		.replace(/\s+/g, "-").replace(/[^\w-]+/g, "")
		.replace(/--+/g, "-").replace(/^-+/, "").replace(/-+$/, "");
}

function intQuery(c: AppContext, key: string): number | undefined {
	const v = c.req.query(key);
	if (!v) return undefined;
	const n = Number(v);
	return Number.isFinite(n) ? Math.max(1, Math.min(Math.floor(n), 100_000)) : undefined;
}

function boolQuery(c: AppContext, key: string): boolean | undefined {
	const v = c.req.query(key);
	if (v === undefined || v === "") return undefined;
	return v === "true" || v === "1";
}

function stringQuery(c: AppContext, key: string, max = 200): string | undefined {
	const value = c.req.query(key);
	return value === undefined ? undefined : value.slice(0, max);
}

function configuredDomains(env: Env): string[] {
	return (env.DOMAINS || "")
		.split(",")
		.map((domain) => domain.trim().toLowerCase().replace(/^@/, ""))
		.filter(Boolean);
}

function isAllowedMailboxAddress(env: Env, address: string): boolean {
	const email = address.trim().toLowerCase();
	const allowedAddresses: readonly string[] = env.EMAIL_ADDRESSES ?? [];
	if (allowedAddresses.length > 0) return allowedAddresses.includes(email);
	const domain = email.split("@")[1];
	return Boolean(domain && configuredDomains(env).includes(domain));
}

function stateChangingOriginAllowed(c: AppContext): boolean {
	const origin = c.req.header("Origin");
	if (!origin) return true;
	try {
		return new URL(origin).host === new URL(c.req.url).host;
	} catch {
		return false;
	}
}

// -- App & middleware -----------------------------------------------

const app = new Hono<MailboxContext>();
app.use("/api/*", async (c, next) => {
	const length = Number(c.req.header("Content-Length") || 0);
	if (length > 32 * 1024 * 1024) return c.json({ error: "Request body exceeds 32 MiB limit" }, 413);
	await next();
});
app.use("/api/*", cors({
	origin: (origin) => {
		// Same-origin requests have no Origin header — allow them.
		if (!origin) return origin;
		// In development, allow localhost for Vite dev server.
		try {
			const url = new URL(origin);
			if (url.hostname === "localhost" || url.hostname === "127.0.0.1") return origin;
		} catch { /* invalid origin */ }
		// Block all other cross-origin requests. The app is served from the
		// same origin as the API, so legitimate browser requests never send
		// an Origin header. Returning undefined omits Access-Control-Allow-Origin.
		return undefined;
	},
}));
app.use("/api/*", async (c, next) => {
	if (["POST", "PUT", "PATCH", "DELETE"].includes(c.req.method) && !stateChangingOriginAllowed(c)) {
		return c.json({ error: "Cross-origin state change rejected" }, 403);
	}
	await next();
});
app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox);
app.onError((error, c) => {
	if (error instanceof z.ZodError) {
		return c.json({ error: "Invalid request", details: error.issues }, 400);
	}
	console.error(JSON.stringify({ event: "request_failed", path: c.req.path, error: error instanceof Error ? error.message : "unknown" }));
	return c.json({ error: "Internal server error" }, 500);
});

// -- Config ---------------------------------------------------------

app.get("/api/v1/config", (c) => {
	const domainsRaw = c.env.DOMAINS || "";
	const domains = domainsRaw.split(",").map((d) => d.trim()).filter(Boolean);
	const emailAddresses = c.env.EMAIL_ADDRESSES ?? [];
	return c.json({ domains, emailAddresses });
});

// -- Mailboxes ------------------------------------------------------

app.get("/api/v1/mailboxes", async (c) => {
	const allMailboxes = await listMailboxes(c.env.BUCKET);
	return c.json(allMailboxes.map((m) => ({ ...m, name: m.id })));
});

app.post("/api/v1/mailboxes", async (c) => {
	if (!stateChangingOriginAllowed(c)) return c.json({ error: "Cross-origin state change rejected" }, 403);
	const { name, settings, email: rawEmail } = CreateMailboxBody.parse(await c.req.json());
	const email = rawEmail.toLowerCase();
	if (!isAllowedMailboxAddress(c.env, email)) {
		return c.json({ error: "Mailbox address is outside the configured domain or address allowlist" }, 403);
	}
	const key = `mailboxes/${email}.json`;
	if (await c.env.BUCKET.head(key)) return c.json({ error: "Mailbox already exists" }, 409);
	const defaultSettings = { fromName: name, autoDraftEnabled: true, autoDraftMaxPerDay: 50, forwarding: { enabled: false, email: "" }, signature: { enabled: false, text: "" }, autoReply: { enabled: false, subject: "", message: "" } };
	const finalSettings = { ...defaultSettings, ...settings };
	await c.env.BUCKET.put(key, JSON.stringify(finalSettings));
	const stub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(email));
	await stub.getFolders();
	return c.json({ id: email, email, name, settings: finalSettings }, 201);
});

app.get("/api/v1/mailboxes/:mailboxId", async (c) => {
	const mailboxId = c.req.param("mailboxId")!;
	const obj = await c.env.BUCKET.get(`mailboxes/${mailboxId}.json`);
	if (!obj) return c.json({ error: "Not found" }, 404);
	return c.json({ id: mailboxId, name: mailboxId, email: mailboxId, settings: await obj.json() });
});

const UpdateMailboxBody = z.object({ settings: MailboxSettingsSchema });

app.put("/api/v1/mailboxes/:mailboxId", async (c) => {
	if (!stateChangingOriginAllowed(c)) return c.json({ error: "Cross-origin state change rejected" }, 403);
	const mailboxId = c.req.param("mailboxId")!;
	let parsed: z.infer<typeof UpdateMailboxBody>;
	try {
		parsed = UpdateMailboxBody.parse(await c.req.json());
	} catch (e) {
		return c.json({ error: "Invalid settings", details: (e as z.ZodError).issues }, 400);
	}
	const { settings } = parsed;
	const key = `mailboxes/${mailboxId}.json`;
	if (!(await c.env.BUCKET.head(key))) return c.json({ error: "Not found" }, 404);
	await c.env.BUCKET.put(key, JSON.stringify(settings));
	return c.json({ id: mailboxId, name: mailboxId, email: mailboxId, settings });
});

app.delete("/api/v1/mailboxes/:mailboxId", async (c) => {
	if (!stateChangingOriginAllowed(c)) return c.json({ error: "Cross-origin state change rejected" }, 403);
	const mailboxId = c.req.param("mailboxId")!;
	const key = `mailboxes/${mailboxId}.json`;
	if (!(await c.env.BUCKET.head(key))) return c.json({ error: "Not found" }, 404);

	// 1. Collect attachment paths before destructive work so failed R2 deletes can be retried.
	const mailboxStub = c.env.MAILBOX.get(c.env.MAILBOX.idFromName(mailboxId));
	const attachments = await mailboxStub.listAttachmentKeys();

	// 2. Batch-delete R2 attachment blobs.
	if (attachments.length > 0) {
		await deleteAttachmentObjects(c.env.BUCKET, attachments.map((attachment) => ({
			email_id: attachment.emailId,
			id: attachment.attachmentId,
			filename: attachment.filename,
			object_key: attachment.objectKey,
		})));
	}

	// 3. Clear Durable Object storage only after external attachment blobs are gone.
	await mailboxStub.destroy();

	// 4. Clear the EmailAgent DO storage. Let failures abort metadata deletion for retry.
	const agentStub = c.env.EMAIL_AGENT.get(c.env.EMAIL_AGENT.idFromName(mailboxId));
	const agentDestroyResponse = await agentStub.fetch(new Request("https://agent/destroy", { method: "DELETE" }));
	if (!agentDestroyResponse.ok) {
		throw new Error(`EmailAgent destroy failed with status ${agentDestroyResponse.status}`);
	}

	// 5. Remove the mailbox metadata key last so a retry is safe if steps above fail.
	await c.env.BUCKET.delete(key);
	return c.body(null, 204);
});

// -- Emails ---------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/emails", async (c: AppContext) => {
	const folder = c.req.query("folder");
	const thread_id = c.req.query("thread_id");
	const threaded = boolQuery(c, "threaded");
	const page = intQuery(c, "page");
	const limit = intQuery(c, "limit");
	const sortColumnRaw = c.req.query("sortColumn");
	const sortColumn = ["id", "subject", "sender", "recipient", "date", "read", "starred"].includes(sortColumnRaw || "") ? sortColumnRaw as "id" | "subject" | "sender" | "recipient" | "date" | "read" | "starred" : undefined;
	const sortDirection = c.req.query("sortDirection") === "ASC" ? "ASC" : c.req.query("sortDirection") === "DESC" ? "DESC" : undefined;
	const stub = c.var.mailboxStub;

	if (threaded && folder) {
		const emails = await stub.getThreadedEmails({ folder, page, limit });
		const totalCount = await stub.countThreadedEmails(folder);
		return c.json({ emails, totalCount });
	}
	const emails = await stub.getEmails({ folder, thread_id, page, limit, sortColumn, sortDirection });
	if (folder) {
		const totalCount = await stub.countEmails({ folder, thread_id });
		return c.json({ emails, totalCount });
	}
	return c.json(emails);
});

app.post("/api/v1/mailboxes/:mailboxId/emails", async (c: AppContext) => {
	if (!stateChangingOriginAllowed(c)) return c.json({ error: "Cross-origin state change rejected" }, 403);
	const mailboxId = c.req.param("mailboxId")!;
	const body = SendEmailRequestSchema.parse(await c.req.json());
	const { to, cc, bcc, from, subject, html, text, attachments, in_reply_to, references, thread_id, source_draft_id } = body;

	let toStr: string, fromEmail: string, fromDomain: string;
	try {
		({ toStr, fromEmail, fromDomain } = validateSender(to, from, mailboxId));
	} catch (e) {
		if (e instanceof SenderValidationError) return c.json({ error: e.message }, 400);
		throw e;
	}

	const stub = c.var.mailboxStub;
	const idempotencyKey = c.req.header("Idempotency-Key")?.trim() || crypto.randomUUID();
	const payloadHash = await hashPayload({ to, cc, bcc, from, subject, html, text, attachments, in_reply_to, references, thread_id, source_draft_id });
	const existing = await stub.getOutboundByIdempotencyKey(idempotencyKey);
	if (existing) {
		if (existing.payloadHash !== payloadHash) return c.json({ error: "Idempotency-Key was already used for a different request" }, 409);
		return c.json({ id: existing.emailId, operationId: existing.operationId, status: existing.status }, 202);
	}
	const rateLimitError = await stub.checkSendRateLimit();
	if (rateLimitError) return c.json({ error: rateLimitError }, 429);
	const { messageId, outgoingMessageId } = generateMessageId(fromDomain);
	let attachmentData: StoredAttachment[] = [];
	try {
		attachmentData = await storeAttachments(c.env.BUCKET, messageId, attachments);
		const now = new Date().toISOString();
		const created = await stub.createOutboundEmail(mailboxId, {
			id: messageId, subject, sender: fromEmail, recipient: toStr,
			cc: cc ? (Array.isArray(cc) ? cc.join(", ") : cc).toLowerCase() : null,
			bcc: bcc ? (Array.isArray(bcc) ? bcc.join(", ") : bcc).toLowerCase() : null,
			date: now, body: html || text || "", body_format: html ? "html" : "text",
			in_reply_to: in_reply_to || null, email_references: references ? JSON.stringify(references) : null,
			thread_id: thread_id || in_reply_to || messageId, message_id: outgoingMessageId,
			raw_headers: JSON.stringify([
			{ key: "from", value: typeof from === "string" ? from : `${from.name} <${from.email}>` },
			{ key: "to", value: Array.isArray(to) ? to.join(", ") : to },
			...(cc ? [{ key: "cc", value: Array.isArray(cc) ? cc.join(", ") : cc }] : []),
			...(bcc ? [{ key: "bcc", value: Array.isArray(bcc) ? bcc.join(", ") : bcc }] : []),
			{ key: "subject", value: subject }, { key: "date", value: new Date().toISOString() },
			{ key: "message-id", value: `<${outgoingMessageId}>` },
			]),
		}, attachmentData, crypto.randomUUID(), idempotencyKey, payloadHash, source_draft_id || null);
		if (!created.ok) {
			await deleteAttachmentObjects(c.env.BUCKET, attachmentData);
			if (created.reason === "idempotency_conflict") return c.json({ error: "Idempotency-Key was already used for a different request" }, 409);
			return c.json({ error: created.reason === "source_not_draft" ? "Source email is not a draft" : "Source draft not found" }, 409);
		}
		if (!created.created) {
			await deleteAttachmentObjects(c.env.BUCKET, attachmentData);
			return c.json({ id: created.emailId, operationId: created.operationId, status: created.status }, 202);
		}
		const queueStatus = await enqueueOutboundEmail(c.env, mailboxId, created.operationId, stub);
		return c.json({ id: created.emailId, operationId: created.operationId, status: "queued", queueStatus }, 202);
	} catch (error) {
		await deleteAttachmentObjects(c.env.BUCKET, attachmentData).catch(() => undefined);
		throw error;
	}
});

app.post("/api/v1/mailboxes/:mailboxId/drafts", async (c: AppContext) => {
	if (!stateChangingOriginAllowed(c)) return c.json({ error: "Cross-origin state change rejected" }, 403);
	const mailboxId = c.req.param("mailboxId")!;
	if (!(await c.var.mailboxStub.checkRateLimit("drafts:hour", 120, 60 * 60))) return c.json({ error: "Draft rate limit exceeded" }, 429);
	const { to, cc, bcc, subject, body, in_reply_to, thread_id, draft_id } = DraftBody.parse(await c.req.json());
	const stub = c.var.mailboxStub;
	const messageId = crypto.randomUUID();
	const now = new Date().toISOString();
	// replaceDraft is a single DO method call — delete + insert are atomic.
	const result = await stub.replaceDraft(draft_id ?? null, {
		id: messageId, subject: subject || "", sender: mailboxId.toLowerCase(),
		recipient: (to || "").toLowerCase(), cc: cc?.toLowerCase() || null, bcc: bcc?.toLowerCase() || null,
		date: now, body, in_reply_to: in_reply_to || null, email_references: null,
		thread_id: thread_id || in_reply_to || messageId,
	}, []);
	if (!result.ok) return c.json({ error: result.reason === "not_draft" ? "Email is not a draft" : "Draft not found" }, 409);
	return c.json({ id: result.id, status: "draft", subject: subject || "", recipient: to || "", date: result.date }, 201);
});

app.get("/api/v1/mailboxes/:mailboxId/emails/:id", async (c: AppContext) => {
	const email = await c.var.mailboxStub.getEmail(c.req.param("id")!);
	if (!email) return c.json({ error: "Email not found" }, 404);
	return new Response(JSON.stringify(email), {
		headers: { "Content-Type": "application/json" },
	});
});

app.get("/api/v1/mailboxes/:mailboxId/delivery/:operationId", async (c: AppContext) => {
	const operation = await c.var.mailboxStub.getOutboundStatus(c.req.param("operationId")!);
	return operation ? c.json(operation) : c.json({ error: "Delivery operation not found" }, 404);
});

app.put("/api/v1/mailboxes/:mailboxId/emails/:id", async (c: AppContext) => {
	const { read, starred } = EmailUpdateBody.parse(await c.req.json());
	const email = await c.var.mailboxStub.updateEmail(c.req.param("id")!, { read, starred });
	return email ? c.json(email) : c.json({ error: "Email not found" }, 404);
});

app.delete("/api/v1/mailboxes/:mailboxId/emails/:id", async (c: AppContext) => {
	const id = c.req.param("id")!;
	const attachments = await c.var.mailboxStub.deleteEmail(id);
	if (attachments === null) return c.json({ error: "Not found" }, 404);
	return c.body(null, 204);
});

app.post("/api/v1/mailboxes/:mailboxId/emails/:id/move", async (c: AppContext) => {
	const { folderId } = MoveEmailBody.parse(await c.req.json());
	const success = await c.var.mailboxStub.moveEmail(c.req.param("id")!, folderId);
	return success ? c.json({ status: "moved" }) : c.json({ error: "Folder not found" }, 400);
});

// -- Threads --------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/threads/:threadId", async (c: AppContext) => {
	return c.json(await c.var.mailboxStub.getThreadEmails(c.req.param("threadId")!));
});

app.post("/api/v1/mailboxes/:mailboxId/threads/:threadId/read", async (c: AppContext) => {
	await c.var.mailboxStub.markThreadRead(c.req.param("threadId")!);
	return c.json({ status: "marked_read" });
});

// -- Reply / Forward ------------------------------------------------

app.post("/api/v1/mailboxes/:mailboxId/emails/:id/reply", handleReplyEmail);
app.post("/api/v1/mailboxes/:mailboxId/emails/:id/forward", handleForwardEmail);

// -- Folders --------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/folders", async (c: AppContext) => c.json(await c.var.mailboxStub.getFolders()));

app.post("/api/v1/mailboxes/:mailboxId/folders", async (c: AppContext) => {
	if (!(await c.var.mailboxStub.checkRateLimit("folders:hour", 20, 60 * 60))) return c.json({ error: "Folder rate limit exceeded" }, 429);
	const { name } = FolderBody.parse(await c.req.json());
	const slug = slugify(name);
	if (!slug) return c.json({ error: "Folder name must contain alphanumeric characters" }, 400);
	const f = await c.var.mailboxStub.createFolder(slug, name);
	return f ? c.json(f, 201) : c.json({ error: "Folder with this name already exists" }, 409);
});

app.put("/api/v1/mailboxes/:mailboxId/folders/:id", async (c: AppContext) => {
	const { name } = FolderBody.parse(await c.req.json());
	const f = await c.var.mailboxStub.updateFolder(c.req.param("id")!, name);
	return f ? c.json(f) : c.json({ error: "Folder not found" }, 404);
});

app.delete("/api/v1/mailboxes/:mailboxId/folders/:id", async (c: AppContext) => {
	const ok = await c.var.mailboxStub.deleteFolder(c.req.param("id")!);
	return ok ? c.body(null, 204) : c.json({ error: "Folder not found or cannot be deleted" }, 400);
});

// -- Search ---------------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/search", async (c: AppContext) => {
	if (!(await c.var.mailboxStub.checkRateLimit("search:minute", 120, 60))) return c.json({ error: "Search rate limit exceeded" }, 429);
	const searchOpts = {
		query: stringQuery(c, "query") || "", folder: stringQuery(c, "folder"), from: stringQuery(c, "from"),
		to: stringQuery(c, "to"), subject: stringQuery(c, "subject"), date_start: stringQuery(c, "date_start", 40),
		date_end: stringQuery(c, "date_end", 40), is_read: boolQuery(c, "is_read"),
		is_starred: boolQuery(c, "is_starred"), has_attachment: boolQuery(c, "has_attachment"),
	};
	const stub = c.var.mailboxStub;
	const emails = await stub.searchEmails({ ...searchOpts, page: intQuery(c, "page"), limit: intQuery(c, "limit") });
	const totalCount = await stub.countSearchResults(searchOpts);
	return c.json({ emails, totalCount });
});

// -- Attachments ----------------------------------------------------

app.get("/api/v1/mailboxes/:mailboxId/emails/:emailId/attachments/:attachmentId", async (c: AppContext) => {
	const emailId = c.req.param("emailId")!;
	const attachmentId = c.req.param("attachmentId")!;
	const attachment = await c.var.mailboxStub.getAttachment(attachmentId);
	if (!attachment) return c.json({ error: "Attachment not found" }, 404);
	const objectKey = attachment.object_key || `attachments/${emailId}/${attachmentId}/${attachment.filename}`;
	const obj = await c.env.BUCKET.get(objectKey);
	if (!obj) return c.json({ error: "Attachment file not found" }, 404);
	const headers = new Headers();
	headers.set("Content-Type", attachment.mimetype);
	const sanitized = attachment.filename.replace(/[\x00-\x1f"\\]/g, "_");
	headers.set("Content-Disposition", `attachment; filename="${sanitized}"; filename*=UTF-8''${encodeURIComponent(attachment.filename)}`);
	return new Response(obj.body, { headers });
});

// -- Receive inbound email ------------------------------------------

const MAX_EMAIL_SIZE = 25 * 1024 * 1024;

/**
 * Parse the sender's Date header into an ISO string.
 * Rejects dates that are more than 2 days in the future (clock skew / spoofing)
 * or before 2000-01-01 (clearly invalid). Falls back to the current time.
 */
function parseSenderDate(raw: string | undefined): string {
	if (!raw) return new Date().toISOString();
	const d = new Date(raw);
	if (isNaN(d.getTime())) return new Date().toISOString();
	const now = Date.now();
	if (d.getTime() > now + 2 * 24 * 60 * 60 * 1000) return new Date().toISOString();
	if (d.getFullYear() < 2000) return new Date().toISOString();
	return d.toISOString();
}

async function streamToArrayBuffer(stream: ReadableStream, streamSize: number) {
	if (streamSize > MAX_EMAIL_SIZE) throw new Error(`Email too large: ${streamSize} bytes exceeds ${MAX_EMAIL_SIZE} byte limit`);
	if (streamSize <= 0) throw new Error(`Invalid stream size: ${streamSize}`);
	const result = new Uint8Array(streamSize);
	let bytesRead = 0;
	const reader = stream.getReader();
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		if (bytesRead + value.length > streamSize) { reader.cancel(); throw new Error(`Stream exceeds declared size`); }
		result.set(value, bytesRead);
		bytesRead += value.length;
	}
	return result;
}

async function hashBytes(value: Uint8Array): Promise<string> {
	const copy = new ArrayBuffer(value.byteLength);
	new Uint8Array(copy).set(value);
	const digest = await crypto.subtle.digest("SHA-256", copy);
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function receiveEmail(event: { raw: ReadableStream; rawSize: number }, env: Env, ctx: ExecutionContext) {
	const rawEmail = await streamToArrayBuffer(event.raw, event.rawSize);
	const parsedEmail = await new PostalMime().parse(rawEmail);

	if (!parsedEmail.to?.length || !parsedEmail.to[0].address) throw new Error("received email with empty to");

	const allRecipients = parsedEmail.to.map((t) => t.address?.toLowerCase()).filter(Boolean) as string[];
	const ccRecipients = (parsedEmail.cc || []).map((e) => e.address?.toLowerCase()).filter(Boolean) as string[];
	const bccRecipients = (parsedEmail.bcc || []).map((e) => e.address?.toLowerCase()).filter(Boolean) as string[];

	let mailboxId: string | undefined;
	mailboxId = allRecipients.find((addr) => isAllowedMailboxAddress(env, addr));
	if (!mailboxId) throw new Error("received email with no valid recipient address");

	const messageId = crypto.randomUUID();
	if (!(await env.BUCKET.head(`mailboxes/${mailboxId}.json`))) { console.log(`Ignoring email for ${mailboxId}: mailbox does not exist`); return; }

	const stub = env.MAILBOX.get(env.MAILBOX.idFromName(mailboxId));
	const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };
	const originalMessageId = parsedEmail.messageId ? extractMsgId(parsedEmail.messageId) : null;
	const inboundKey = originalMessageId
		? `message:${mailboxId}:${originalMessageId.toLowerCase()}`
		: `raw:${mailboxId}:${await hashBytes(rawEmail)}`;
	if (await stub.hasInboundEmail(inboundKey)) return;

	const attachmentData: StoredAttachment[] = [];
	try {
		let totalAttachmentSize = 0;
		if (parsedEmail.attachments) {
			if (parsedEmail.attachments.length > 20) throw new Error("Too many inbound attachments");
			for (const att of parsedEmail.attachments) {
				const attId = crypto.randomUUID();
				const filename = (att.filename || "untitled").slice(0, 255).replace(/[\/\\:*?"<>|\x00-\x1f]/g, "_");
				const objectKey = `attachments/${messageId}/${attId}/${filename}`;
				const size = typeof att.content === "string" ? att.content.length : att.content.byteLength;
				if (size > 10 * 1024 * 1024) throw new Error("Inbound attachment exceeds 10 MiB limit");
				totalAttachmentSize += size;
				if (totalAttachmentSize > 20 * 1024 * 1024) throw new Error("Inbound attachments exceed 20 MiB total limit");
				await env.BUCKET.put(objectKey, att.content);
				attachmentData.push({ id: attId, email_id: messageId, filename, mimetype: att.mimeType,
					size, content_id: att.contentId || null, disposition: att.disposition || "attachment", object_key: objectKey });
			}
		}
	} catch (error) {
		await deleteAttachmentObjects(env.BUCKET, attachmentData).catch(() => undefined);
		throw error;
	}

	const inReplyTo = parsedEmail.inReplyTo ? extractMsgId(parsedEmail.inReplyTo) : null;
	const emailReferences = parsedEmail.references ? parsedEmail.references.split(/\s+/).filter(Boolean).map(extractMsgId) : [];
	let threadId = emailReferences[0] || inReplyTo || messageId;

	if (!inReplyTo && emailReferences.length === 0) {
		const subjectThread = await stub.findThreadBySubject(parsedEmail.subject || "", parsedEmail.from?.address || undefined);
		if (subjectThread) threadId = subjectThread;
	}

	let created: { duplicate: boolean; id: string };
	try {
		created = await stub.createInboundEmail({
			id: messageId, subject: parsedEmail.subject || "",
			sender: (parsedEmail.from?.address || "").toLowerCase(), recipient: allRecipients.join(", "),
			cc: ccRecipients.join(", ") || null, bcc: bccRecipients.join(", ") || null,
			date: parseSenderDate(parsedEmail.date),
			body: parsedEmail.html || parsedEmail.text || "",
			in_reply_to: inReplyTo, email_references: emailReferences.length > 0 ? JSON.stringify(emailReferences) : null,
			thread_id: threadId, message_id: originalMessageId, raw_headers: JSON.stringify(parsedEmail.headers),
			inbound_key: inboundKey, body_format: parsedEmail.html ? "html" : "text",
		}, attachmentData);
	} catch (error) {
		await deleteAttachmentObjects(env.BUCKET, attachmentData).catch(() => undefined);
		throw error;
	}
	if (created.duplicate) {
		await deleteAttachmentObjects(env.BUCKET, attachmentData).catch(() => undefined);
		return;
	}

	const settingsObj = await env.BUCKET.get(`mailboxes/${mailboxId}.json`);
	const settings = settingsObj ? await settingsObj.json<{ autoDraftEnabled?: boolean }>() : {};
	if (settings.autoDraftEnabled !== false) {
		const autoDraftJob = {
			mailboxId,
			emailId: messageId,
			sender: (parsedEmail.from?.address || "").toLowerCase(),
			subject: parsedEmail.subject || "",
			threadId,
		};
		ctx.waitUntil(env.AUTO_DRAFT_QUEUE.send(autoDraftJob).catch(async (error) => {
			console.error(JSON.stringify({ event: "auto_draft_queue_enqueue_failed", mailboxId, emailId: messageId, error: error instanceof Error ? error.message : "unknown" }));
			try {
				await stub.scheduleAutoDraftRetry(messageId, mailboxId);
			} catch (scheduleError) {
				console.error(JSON.stringify({ event: "auto_draft_retry_schedule_failed", mailboxId, emailId: messageId, error: scheduleError instanceof Error ? scheduleError.message : "unknown" }));
			}
		}));
	}
}

export { app, receiveEmail };
