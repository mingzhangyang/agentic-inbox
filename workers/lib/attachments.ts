// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Shared attachment storage logic.
 * Eliminates the triplicated atob → Uint8Array → R2.put pattern.
 */
import type { Env } from "../types";

export interface StoredAttachment {
	id: string;
	email_id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id: string | null;
	disposition: string;
	object_key: string;
}

export const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024;
export const MAX_TOTAL_ATTACHMENT_SIZE = 20 * 1024 * 1024;

export function attachmentObjectKey(emailId: string, attachmentId: string, filename: string) {
	return `attachments/${emailId}/${attachmentId}/${filename}`;
}

export async function deleteAttachmentObjects(bucket: R2Bucket, attachments: Array<{
	email_id?: string;
	id: string;
	filename: string;
	object_key?: string | null;
}>) {
	const keys = attachments.map((attachment) => attachment.object_key || attachmentObjectKey(
		attachment.email_id || "",
		attachment.id,
		attachment.filename,
	));
	for (let index = 0; index < keys.length; index += 1000) {
		await bucket.delete(keys.slice(index, index + 1000));
	}
}

/**
 * Store base64-encoded attachments to R2 and return metadata for the DO.
 */
export async function storeAttachments(
	bucket: Env["BUCKET"],
	emailId: string,
	attachments?: {
		content: string;
		filename: string;
		type: string;
		disposition: string;
		contentId?: string;
	}[],
): Promise<StoredAttachment[]> {
	if (!attachments?.length) return [];
	if (attachments.length > 20) throw new Error("Too many attachments");

	const results: StoredAttachment[] = [];
	let totalSize = 0;
	try {
		for (const att of attachments) {
			if (att.disposition === "inline" && !att.contentId) {
				throw new Error("Inline attachments require a content ID");
			}
			if (!/^[A-Za-z0-9+/]*={0,2}$/.test(att.content) || att.content.length % 4 === 1) {
				throw new Error("Attachment content must be valid base64");
			}
			const attachmentId = crypto.randomUUID();
			// Sanitize filename to prevent path traversal in R2 keys
			const safeFilename = (att.filename || "untitled").slice(0, 255).replace(/[\/\\:*?"<>|\x00-\x1f]/g, "_");
			const key = attachmentObjectKey(emailId, attachmentId, safeFilename);
			const binaryStr = atob(att.content);
			const bytes = Uint8Array.from(binaryStr, (c) => c.charCodeAt(0));
			if (bytes.byteLength > MAX_ATTACHMENT_SIZE) throw new Error("Attachment exceeds 10 MiB limit");
			totalSize += bytes.byteLength;
			if (totalSize > MAX_TOTAL_ATTACHMENT_SIZE) throw new Error("Attachments exceed 20 MiB total limit");
			await bucket.put(key, bytes);
			results.push({
				id: attachmentId,
				email_id: emailId,
				filename: safeFilename,
				mimetype: att.type,
				size: bytes.byteLength,
				content_id: att.contentId || null,
				disposition: att.disposition,
				object_key: key,
			});
		}
	} catch (error) {
		await deleteAttachmentObjects(bucket, results).catch(() => undefined);
		throw error;
	}
	return results;
}
