// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { sqliteTable, text, integer } from "drizzle-orm/sqlite-core";

export const folders = sqliteTable("folders", {
	id: text("id").primaryKey(),
	name: text("name").notNull().unique(),
	is_deletable: integer("is_deletable").notNull().default(1),
});

export const emails = sqliteTable("emails", {
	id: text("id").primaryKey(),
	folder_id: text("folder_id")
		.notNull()
		.references(() => folders.id, { onDelete: "cascade" }),
	subject: text("subject"),
	sender: text("sender"),
	recipient: text("recipient"),
	cc: text("cc"),
	bcc: text("bcc"),
	date: text("date"),
	read: integer("read").default(0),
	starred: integer("starred").default(0),
	body: text("body"),
	body_format: text("body_format").notNull().default("html"),
	in_reply_to: text("in_reply_to"),
	email_references: text("email_references"),
	thread_id: text("thread_id"),
	message_id: text("message_id"),
	raw_headers: text("raw_headers"),
	delivery_status: text("delivery_status").notNull().default("sent"),
	delivery_operation_id: text("delivery_operation_id"),
	source_draft_id: text("source_draft_id"),
	inbound_key: text("inbound_key"),
});

export const attachments = sqliteTable("attachments", {
	id: text("id").primaryKey(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	filename: text("filename").notNull(),
	mimetype: text("mimetype").notNull(),
	size: integer("size").notNull(),
	content_id: text("content_id"),
	disposition: text("disposition"),
	object_key: text("object_key"),
});

export const outbox = sqliteTable("outbox", {
	operation_id: text("operation_id").primaryKey(),
	mailbox_id: text("mailbox_id").notNull(),
	email_id: text("email_id")
		.notNull()
		.references(() => emails.id, { onDelete: "cascade" }),
	idempotency_key: text("idempotency_key").notNull().unique(),
	payload_hash: text("payload_hash").notNull(),
	status: text("status").notNull().default("queued"),
	attempts: integer("attempts").notNull().default(0),
	lease_until: integer("lease_until"),
	next_attempt_at: integer("next_attempt_at"),
	provider_message_id: text("provider_message_id"),
	last_error: text("last_error"),
	created_at: integer("created_at").notNull(),
	updated_at: integer("updated_at").notNull(),
});

export const rateLimits = sqliteTable("rate_limits", {
	key: text("key").primaryKey(),
	window_start: integer("window_start").notNull(),
	count: integer("count").notNull().default(0),
});

export const agentJobs = sqliteTable("agent_jobs", {
	email_id: text("email_id").primaryKey(),
	mailbox_id: text("mailbox_id").notNull(),
	status: text("status").notNull().default("queued"),
	attempts: integer("attempts").notNull().default(0),
	lease_until: integer("lease_until"),
	updated_at: integer("updated_at").notNull(),
});
