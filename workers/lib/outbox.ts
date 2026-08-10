// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { sendEmail, type SendEmailParams } from "../email-sender";
import type { MailboxDO } from "../durableObject";
import type { Env } from "../types";
import { buildThreadingHeaders, getMailboxStub } from "./email-helpers";
import { deleteAttachmentObjects } from "./attachments";

export interface OutboundQueueMessage {
	mailboxId: string;
	operationId: string;
}

export async function hashPayload(value: unknown): Promise<string> {
	const encoded = new TextEncoder().encode(JSON.stringify(value));
	const digest = await crypto.subtle.digest("SHA-256", encoded);
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
	let result = "";
	const chunkSize = 0x8000;
	for (let index = 0; index < bytes.length; index += chunkSize) {
		result += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
	}
	return btoa(result);
}

async function buildSendParams(
	email: Awaited<ReturnType<DurableObjectStub<MailboxDO>["getEmail"]>> & { attachments?: Array<{
		id: string;
		filename: string;
		mimetype: string;
		disposition?: string | null;
		content_id?: string | null;
		object_key?: string | null;
	}> },
	bucket: R2Bucket,
): Promise<SendEmailParams> {
	const attachments = [] as NonNullable<SendEmailParams["attachments"]>;
	for (const attachment of email.attachments ?? []) {
		const key = attachment.object_key || `attachments/${email.id}/${attachment.id}/${attachment.filename}`;
		const object = await bucket.get(key);
		if (!object) throw new Error(`Attachment object is missing: ${attachment.id}`);
		attachments.push({
			content: bytesToBase64(new Uint8Array(await object.arrayBuffer())),
			filename: attachment.filename,
			type: attachment.mimetype,
			disposition: attachment.disposition === "inline" ? "inline" : "attachment",
			...(attachment.content_id ? { contentId: attachment.content_id } : {}),
		});
	}

	const headers: Record<string, string> = {};
	if (email.message_id) headers["Message-ID"] = `<${email.message_id}>`;
	if (email.in_reply_to) {
		let references: string[] = [];
		if (email.email_references) {
			try {
				const parsed = JSON.parse(email.email_references);
				if (Array.isArray(parsed)) references = parsed.filter((value): value is string => typeof value === "string");
			} catch {
				// Ignore malformed legacy references; In-Reply-To is still useful.
			}
		}
		Object.assign(headers, buildThreadingHeaders(email.in_reply_to, references));
	}

	return {
		to: email.recipient || "",
		from: email.sender || "",
		subject: email.subject || "",
		...(email.body_format === "text" ? { text: email.body || "" } : { html: email.body || "" }),
		...(email.cc ? { cc: email.cc } : {}),
		...(email.bcc ? { bcc: email.bcc } : {}),
		...(attachments.length > 0 ? { attachments } : {}),
		...(Object.keys(headers).length > 0 ? { headers } : {}),
	};
}

function dryRunEmails(env: Env): boolean {
	return env.DRY_RUN_EMAILS?.trim().toLowerCase() !== "false";
}

/**
 * Process one queue message with a DO lease. Delivery is at-least-once:
 * the stable Message-ID and operation id make retries observable and safe
 * to reconcile, while the provider itself remains the final deduplication
 * boundary.
 */
export async function processOutboundMessage(
	message: Message<OutboundQueueMessage>,
	env: Env,
): Promise<void> {
	const { mailboxId, operationId } = message.body;
	const stub = getMailboxStub(env, mailboxId);
	const claim = await stub.claimOutboundDelivery(operationId);
	if (claim.status !== "claimed") {
		if (claim.status === "pending") message.retry({ delaySeconds: 60 });
		else message.ack();
		return;
	}

	try {
		const email = await stub.getEmail(claim.emailId);
		if (!email) throw new Error("Outbound email record is missing");
		let providerMessageId = "dry-run";
		if (!dryRunEmails(env)) {
			const params = await buildSendParams(email, env.BUCKET);
			const result = await sendEmail(env.EMAIL, params);
			providerMessageId = result.messageId;
		}
		const completed = await stub.completeOutboundDelivery(operationId, providerMessageId);
		if (completed.draftAttachments.length > 0) {
			await deleteAttachmentObjects(env.BUCKET, completed.draftAttachments);
		}
		message.ack();
	} catch (error) {
		const failure = await stub.failOutboundDelivery(
			operationId,
			error instanceof Error ? error.message : "Unknown delivery error",
		);
		if (failure.retry) {
			message.retry({ delaySeconds: Math.min(60, 2 ** Math.max(0, failure.attempts - 1)) });
		} else {
			message.ack();
		}
	}
}

export async function enqueueOutboundEmail(
	env: Env,
	mailboxId: string,
	operationId: string,
	stub: DurableObjectStub<MailboxDO>,
): Promise<"queued" | "scheduled"> {
	try {
		await env.OUTBOUND_QUEUE.send({ mailboxId, operationId });
		return "queued";
	} catch (error) {
		console.error(JSON.stringify({ event: "outbound_queue_enqueue_failed", mailboxId, operationId, error: error instanceof Error ? error.message : "unknown" }));
		await stub.scheduleOutboundRetry(operationId);
		return "scheduled";
	}
}
