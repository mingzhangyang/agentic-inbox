// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import type { Context } from "hono";
import { deleteAttachmentObjects, storeAttachments } from "../lib/attachments";
import type { EmailFull } from "../lib/schemas";
import {
	validateSender,
	SenderValidationError,
	generateMessageId,
	buildReferencesChain,
	resolveOriginalEmail,
} from "../lib/email-helpers";
import { SendEmailRequestSchema } from "../lib/schemas";
import { Folders } from "../../shared/folders";
import type { MailboxContext } from "../lib/mailbox";
import { enqueueOutboundEmail, hashPayload } from "../lib/outbox";

type AppContext = Context<MailboxContext>;

export async function handleReplyEmail(c: AppContext) {
	const mailboxId = c.req.param("mailboxId") ?? "";
	const id = c.req.param("id") ?? "";
	const body = SendEmailRequestSchema.parse(await c.req.json());
	const { to, cc, bcc, from, subject, html, text, attachments, source_draft_id } = body;

	const stub = c.var.mailboxStub;
	const rawOriginal = (await stub.getEmail(id)) as EmailFull | null;

	if (!rawOriginal) {
		return c.json({ error: "Original email not found" }, 404);
	}

	const originalEmail = await resolveOriginalEmail(stub, rawOriginal);
	const { originalMsgId, references, threadId: thread_id } = buildReferencesChain(originalEmail);

	let toStr: string, fromEmail: string, fromDomain: string;
	try {
		({ toStr, fromEmail, fromDomain } = validateSender(to, from, mailboxId));
	} catch (e) {
		if (e instanceof SenderValidationError) return c.json({ error: e.message }, 400);
		throw e;
	}

	const idempotencyKey = c.req.header("Idempotency-Key")?.trim() || crypto.randomUUID();
	const payloadHash = await hashPayload({ kind: "reply", id, to, cc, bcc, from, subject, html, text, attachments, source_draft_id });
	const existing = await stub.getOutboundByIdempotencyKey(idempotencyKey);
	if (existing) {
		if (existing.payloadHash !== payloadHash) return c.json({ error: "Idempotency-Key was already used for a different request" }, 409);
		return c.json({ id: existing.emailId, operationId: existing.operationId, status: existing.status }, 202);
	}

	const rateLimitError = await stub.checkSendRateLimit();
	if (rateLimitError) {
		return c.json({ error: rateLimitError }, 429);
	}

	const { messageId, outgoingMessageId } = generateMessageId(fromDomain);
	let attachmentData = [] as Awaited<ReturnType<typeof storeAttachments>>;
	try {
		attachmentData = await storeAttachments(c.env.BUCKET, messageId, attachments);
		const created = await stub.createOutboundEmail(mailboxId, {
			id: messageId,
			subject,
			sender: fromEmail,
			recipient: toStr,
			cc: cc ? (Array.isArray(cc) ? cc.join(", ") : cc).toLowerCase() : null,
			bcc: bcc ? (Array.isArray(bcc) ? bcc.join(", ") : bcc).toLowerCase() : null,
			date: new Date().toISOString(), body_format: html ? "html" : "text",
			body: html || text || "",
			in_reply_to: originalMsgId,
			email_references: JSON.stringify(references),
			thread_id: thread_id,
			message_id: outgoingMessageId,
			raw_headers: JSON.stringify([
				{ key: "from", value: typeof from === "string" ? from : `${from.name} <${from.email}>` },
				{ key: "to", value: Array.isArray(to) ? to.join(", ") : to },
				...(cc ? [{ key: "cc", value: Array.isArray(cc) ? cc.join(", ") : cc }] : []),
				...(bcc ? [{ key: "bcc", value: Array.isArray(bcc) ? bcc.join(", ") : bcc }] : []),
				{ key: "subject", value: subject },
				{ key: "date", value: new Date().toISOString() },
				{ key: "message-id", value: `<${outgoingMessageId}>` },
				...(originalMsgId ? [{ key: "in-reply-to", value: `<${originalMsgId}>` }] : []),
				...(references.length > 0 ? [{ key: "references", value: references.map((r: string) => `<${r}>`).join(" ") }] : []),
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

		await stub.markThreadRead(thread_id);
		const queueStatus = await enqueueOutboundEmail(c.env, mailboxId, created.operationId, stub);
		return c.json({ id: created.emailId, operationId: created.operationId, status: "queued", queueStatus }, 202);
	} catch (error) {
		await deleteAttachmentObjects(c.env.BUCKET, attachmentData).catch(() => undefined);
		throw error;
	}
}

export async function handleForwardEmail(c: AppContext) {
	const mailboxId = c.req.param("mailboxId") ?? "";
	const id = c.req.param("id") ?? "";
	const body = SendEmailRequestSchema.parse(await c.req.json());
	const { to, cc, bcc, from, subject, html, text, attachments, source_draft_id } = body;

	const stub = c.var.mailboxStub;
	const rawOriginal = (await stub.getEmail(id)) as EmailFull | null;

	if (!rawOriginal) {
		return c.json({ error: "Original email not found" }, 404);
	}

	await resolveOriginalEmail(stub, rawOriginal);

	let toStr: string, fromEmail: string, fromDomain: string;
	try {
		({ toStr, fromEmail, fromDomain } = validateSender(to, from, mailboxId));
	} catch (e) {
		if (e instanceof SenderValidationError) return c.json({ error: e.message }, 400);
		throw e;
	}

	const idempotencyKey = c.req.header("Idempotency-Key")?.trim() || crypto.randomUUID();
	const payloadHash = await hashPayload({ kind: "forward", id, to, cc, bcc, from, subject, html, text, attachments, source_draft_id });
	const existing = await stub.getOutboundByIdempotencyKey(idempotencyKey);
	if (existing) {
		if (existing.payloadHash !== payloadHash) return c.json({ error: "Idempotency-Key was already used for a different request" }, 409);
		return c.json({ id: existing.emailId, operationId: existing.operationId, status: existing.status }, 202);
	}

	const rateLimitError = await stub.checkSendRateLimit();
	if (rateLimitError) {
		return c.json({ error: rateLimitError }, 429);
	}

	const { messageId, outgoingMessageId } = generateMessageId(fromDomain);
	let attachmentData = [] as Awaited<ReturnType<typeof storeAttachments>>;
	try {
		attachmentData = await storeAttachments(c.env.BUCKET, messageId, attachments);
		const created = await stub.createOutboundEmail(mailboxId, {
			id: messageId,
			subject,
			sender: fromEmail,
			recipient: toStr,
			cc: cc ? (Array.isArray(cc) ? cc.join(", ") : cc).toLowerCase() : null,
			bcc: bcc ? (Array.isArray(bcc) ? bcc.join(", ") : bcc).toLowerCase() : null,
			date: new Date().toISOString(), body_format: html ? "html" : "text",
			body: html || text || "",
			in_reply_to: null,
			email_references: null,
			thread_id: messageId,
			message_id: outgoingMessageId,
			raw_headers: JSON.stringify([
				{ key: "from", value: typeof from === "string" ? from : `${from.name} <${from.email}>` },
				{ key: "to", value: Array.isArray(to) ? to.join(", ") : to },
				...(cc ? [{ key: "cc", value: Array.isArray(cc) ? cc.join(", ") : cc }] : []),
				...(bcc ? [{ key: "bcc", value: Array.isArray(bcc) ? bcc.join(", ") : bcc }] : []),
				{ key: "subject", value: subject },
				{ key: "date", value: new Date().toISOString() },
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
}
