// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Email sending via Cloudflare Email Service binding.
 *
 * Uses the `send_email` Worker binding (`env.EMAIL.send()`) to send emails.
 *
 * See: https://developers.cloudflare.com/email-service/api/send-emails/workers-api/
 */

export interface SendEmailParams {
	to: string | string[];
	from: string | { email: string; name: string };
	subject: string;
	html?: string;
	text?: string;
	cc?: string | string[];
	bcc?: string | string[];
	replyTo?: string | { email: string; name: string };
	attachments?: {
		content: string; // base64 encoded
		filename: string;
		type: string;
		disposition: "attachment" | "inline";
		contentId?: string;
	}[];
	headers?: Record<string, string>;
}

/**
 * Send an email using the Cloudflare Email Service binding.
 *
 * @param binding  - The `EMAIL` SendEmail binding from env
 * @param params   - Email parameters (to, from, subject, body, etc.)
 * @returns The send result with messageId
 * @throws On validation or delivery errors (error has `.code` property)
 */
export async function sendEmail(
	binding: SendEmail,
	params: SendEmailParams,
): Promise<{ messageId: string }> {
	type EmailSendOptions = {
		to: string | string[];
		from: string | { email: string; name: string };
		subject: string;
		html?: string;
		text?: string;
		cc?: string | string[];
		bcc?: string | string[];
		replyTo?: string | { email: string; name: string };
		attachments?: EmailAttachment[];
		headers?: Record<string, string>;
	};

	const emailAttachments: EmailAttachment[] = (params.attachments ?? []).map((attachment) => {
		if (attachment.disposition === "inline") {
			if (!attachment.contentId) throw new Error(`Inline attachment ${attachment.filename} is missing a content ID`);
			return {
				content: attachment.content,
				filename: attachment.filename,
				type: attachment.type,
				disposition: "inline" as const,
				contentId: attachment.contentId,
			};
		}
		return {
			content: attachment.content,
			filename: attachment.filename,
			type: attachment.type,
			disposition: "attachment" as const,
		};
	});

	const message: EmailSendOptions = {
		to: params.to,
		from: params.from,
		subject: params.subject,
		...(emailAttachments.length > 0 ? { attachments: emailAttachments } : {}),
	};

	if (params.html) message.html = params.html;
	if (params.text) message.text = params.text;
	if (params.cc) message.cc = params.cc;
	if (params.bcc) message.bcc = params.bcc;
	if (params.replyTo) message.replyTo = params.replyTo;

	if (params.headers && Object.keys(params.headers).length > 0) {
		message.headers = params.headers;
	}

	const result = await binding.send(message);
	return { messageId: result.messageId };
}
