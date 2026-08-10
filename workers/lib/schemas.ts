// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Shared types and Zod schemas for email data.
 *
 * Types (from email-types.ts): used by the agent, MCP server, and route
 * handlers to avoid `as any` casting.
 *
 * Zod schemas: used across route handlers to eliminate duplication.
 */
import { z } from "zod";

// ── TypeScript Interfaces ──────────────────────────────────────────

export interface EmailMetadata {
	id: string;
	subject: string;
	sender: string;
	recipient: string;
	cc?: string | null;
	bcc?: string | null;
	date: string;
	read: boolean;
	starred: boolean;
	in_reply_to?: string | null;
	email_references?: string | null;
	thread_id?: string | null;
	folder_id?: string | null;
	snippet?: string | null;
}

export interface EmailFull extends EmailMetadata {
	body?: string | null;
	body_format?: "html" | "text" | string | null;
	message_id?: string | null;
	raw_headers?: string | null;
	delivery_status?: string | null;
	attachments?: AttachmentInfo[];
}

export interface AttachmentInfo {
	id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id?: string | null;
	disposition?: string | null;
	object_key?: string | null;
}

// ── Zod Schemas ────────────────────────────────────────────────────

export const MailboxSettingsSchema = z
	.object({
		fromName: z.string().max(100).optional(),
		agentSystemPrompt: z.string().max(10_000).optional(),
		autoDraftEnabled: z.boolean().optional(),
		autoDraftMaxPerDay: z.number().int().min(1).max(200).optional(),
		forwarding: z
			.object({
				enabled: z.boolean(),
				email: z.union([z.string().email(), z.literal("")]).optional(),
			})
			.strict()
			.optional(),
		signature: z
			.object({
				enabled: z.boolean(),
				text: z.string().max(5_000).optional(),
			})
			.strict()
			.optional(),
		autoReply: z
			.object({
				enabled: z.boolean(),
				subject: z.string().max(200).optional(),
				message: z.string().max(5_000).optional(),
			})
			.strict()
			.optional(),
	})
	.strict();

export type MailboxSettings = z.infer<typeof MailboxSettingsSchema>;

const RecipientFieldSchema = z.union([
	z.string().email(),
	z.array(z.string().email()).min(1).max(20),
]);

export const MAX_BODY_LENGTH = 1024 * 1024;
export const MAX_SUBJECT_LENGTH = 200;

export const ErrorResponseSchema = z.object({
	error: z.string(),
});

export const SendEmailRequestSchema = z
	.object({
		to: RecipientFieldSchema,
		cc: RecipientFieldSchema.optional(),
		bcc: RecipientFieldSchema.optional(),
		from: z.union([
			z.string().email(),
			z.object({ email: z.string().email(), name: z.string().max(100) }).strict(),
		]),
		subject: z.string().max(MAX_SUBJECT_LENGTH),
		html: z.string().max(MAX_BODY_LENGTH).optional(),
		text: z.string().max(MAX_BODY_LENGTH).optional(),
		attachments: z
			.array(
				z.object({
					content: z.string().max(14_000_000), // base64 encoded
					filename: z.string().min(1).max(255),
					type: z.string().min(1).max(128),
					disposition: z.enum(["attachment", "inline"]),
					contentId: z.string().max(255).optional(),
				}).strict().superRefine((attachment, context) => {
					if (attachment.disposition === "inline" && !attachment.contentId) {
						context.addIssue({ code: z.ZodIssueCode.custom, message: "Inline attachments require contentId", path: ["contentId"] });
					}
				}),
			)
			.max(20)
			.optional(),
		in_reply_to: z.string().optional(),
		references: z.array(z.string()).optional(),
		thread_id: z.string().optional(),
		source_draft_id: z.string().optional(),
	})
	.strict()
	.refine((data) => data.html || data.text, {
		message: "Either 'html' or 'text' must be provided",
	});

export const SendEmailResponseSchema = z.object({
	id: z.string(),
	status: z.string(),
});
