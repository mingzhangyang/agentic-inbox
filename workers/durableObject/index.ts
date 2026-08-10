// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { DurableObject } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/durable-sqlite";
import { eq, and, or, asc, desc, sql } from "drizzle-orm";
import type { SQL } from "drizzle-orm";
import * as schema from "../db/schema";
import { Folders } from "../../shared/folders";
import type { Env } from "../types";
import { applyMigrations, mailboxMigrations } from "./migrations";
import { deleteAttachmentObjects } from "../lib/attachments";

/**
 * SQL expression to normalize email subjects by stripping common
 * reply/forward prefixes (Re:, Fwd:, FW:, AW:, WG:, Réf:, SV:).
 * Used for conversation grouping. Hardcoded to the `subject` column.
 */
const NORMALIZED_SUBJECT_SQL = `LOWER(TRIM(
	REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(
		LOWER(subject),
		'aw: ', ''), 'wg: ', ''), 'réf: ', ''), 'sv: ', ''),
		're: ', ''), 'fwd: ', ''), 'fw: ', '')
))`;

const ALLOWED_SORT_COLUMNS = [
	"id",
	"subject",
	"sender",
	"recipient",
	"date",
	"read",
	"starred",
] as const;

type SortColumn = (typeof ALLOWED_SORT_COLUMNS)[number];

type SqlRow = Record<string, SqlStorageValue>;
type EmailSqlRow = SqlRow & {
	id: string;
	read: number;
	starred: number;
	date: string | null;
	thread_id: string | null;
	folder_id: string;
	body: string | null;
};
type AttachmentSqlRow = SqlRow & {
	id: string;
	email_id: string;
	filename: string;
};
type ThreadedEmailRow = SqlRow & {
	id: string;
	subject: string | null;
	sender: string | null;
	recipient: string | null;
	date: string | null;
	read: number;
	starred: number;
	thread_id: string | null;
	folder_id: string;
	in_reply_to: string | null;
	email_references: string | null;
	snippet: string | null;
	thread_count: number;
	thread_unread_count: number;
	participants: string | null;
	needs_reply?: number;
	has_draft?: number;
};
type ThreadCandidateRow = SqlRow & {
	thread_id: string;
	subject: string | null;
	senders: string | null;
	recipients: string | null;
};

/**
 * Map SortColumn string names to Drizzle column references for safe
 * ORDER BY construction (no string interpolation into SQL).
 */
const SORT_COLUMN_MAP = {
	id: schema.emails.id,
	subject: schema.emails.subject,
	sender: schema.emails.sender,
	recipient: schema.emails.recipient,
	date: schema.emails.date,
	read: schema.emails.read,
	starred: schema.emails.starred,
} satisfies Record<SortColumn, typeof schema.emails[keyof typeof schema.emails]>;

interface SearchFilterOptions {
	query: string;
	folder?: string;
	from?: string;
	to?: string;
	subject?: string;
	date_start?: string;
	date_end?: string;
	is_read?: boolean;
	is_starred?: boolean;
	has_attachment?: boolean;
}

interface GetEmailsOptions {
	folder?: string;
	thread_id?: string;
	page?: number;
	limit?: number;
	sortColumn?: SortColumn;
	sortDirection?: "ASC" | "DESC";
}

interface EmailData {
	id: string;
	subject: string;
	sender: string;
	recipient: string;
	cc?: string | null;
	bcc?: string | null;
	date: string;
	body: string;
	body_format?: "html" | "text" | string | null;
	read?: boolean;
	starred?: boolean;
	in_reply_to?: string | null;
	email_references?: string | null;
	thread_id?: string | null;
	message_id?: string | null;
	raw_headers?: string | null;
	delivery_status?: string | null;
	delivery_operation_id?: string | null;
	source_draft_id?: string | null;
	inbound_key?: string | null;
}

interface AttachmentData {
	id: string;
	email_id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id?: string | null;
	disposition?: string | null;
	object_key?: string | null;
}

export type DraftReplacementResult =
	| { ok: true; id: string; date: string }
	| { ok: false; reason: "not_found" | "not_draft" };

export type OutboxClaimResult =
	| { status: "missing" | "sent" | "failed" | "pending"; operationId: string }
	| { status: "claimed"; operationId: string; emailId: string; attempts: number };

export class MailboxDO extends DurableObject<Env> {
	declare __DURABLE_OBJECT_BRAND: never;
	db: ReturnType<typeof drizzle>;

	constructor(state: DurableObjectState, env: Env) {
		super(state, env);
		this.db = drizzle(this.ctx.storage, { schema });
		this.ctx.blockConcurrencyWhile(async () => {
			applyMigrations(this.ctx.storage.sql, mailboxMigrations, this.ctx.storage);
		});
	}

	// ── Email CRUD (Drizzle) ───────────────────────────────────────

	async getEmails(options: GetEmailsOptions = {}) {
		const {
			folder,
			thread_id,
			page = 1,
			limit: rawLimit = 25,
			sortColumn: rawSortColumn = "date",
			sortDirection = "DESC",
		} = options;

		// Cap pagination limit to prevent unbounded queries
		const limit = Math.min(Math.max(rawLimit, 1), 100);

		const sortColumn: SortColumn = ALLOWED_SORT_COLUMNS.includes(
			rawSortColumn as SortColumn,
		)
			? rawSortColumn
			: "date";

		const offset = (page - 1) * limit;

		const conditions: SQL[] = [];
		if (folder) {
			conditions.push(
				sql`${schema.emails.folder_id} = (SELECT id FROM folders WHERE name = ${folder} OR id = ${folder} LIMIT 1)`,
			);
		}
		if (thread_id) {
			conditions.push(eq(schema.emails.thread_id, thread_id));
		}

		const orderCol = SORT_COLUMN_MAP[sortColumn];
		const orderDir = sortDirection === "ASC" ? asc(orderCol) : desc(orderCol);

		const result = this.db
			.select({
				id: schema.emails.id,
				subject: schema.emails.subject,
				sender: schema.emails.sender,
				recipient: schema.emails.recipient,
				cc: schema.emails.cc,
				bcc: schema.emails.bcc,
				date: schema.emails.date,
				read: schema.emails.read,
				starred: schema.emails.starred,
				in_reply_to: schema.emails.in_reply_to,
				email_references: schema.emails.email_references,
				thread_id: schema.emails.thread_id,
				folder_id: schema.emails.folder_id,
				snippet: sql<string>`SUBSTR(${schema.emails.body}, 1, 300)`,
			})
			.from(schema.emails)
			.where(conditions.length > 0 ? and(...conditions) : undefined)
			.orderBy(orderDir)
			.limit(limit)
			.offset(offset)
			.all();

		return result.map((email) => ({
			...email,
			read: !!email.read,
			starred: !!email.starred,
		}));
	}

	/**
	 * Count total emails matching the given filters (for pagination).
	 */
	async countEmails(options: { folder?: string; thread_id?: string } = {}) {
		const { folder, thread_id } = options;
		const conditions: string[] = [];
		const params: (string | number)[] = [];

		if (folder) {
			conditions.push(
				"folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)",
			);
			params.push(folder);
		}

		if (thread_id) {
			conditions.push(`thread_id = ?${params.length + 1}`);
			params.push(thread_id);
		}

		const where =
			conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
		const row = [
			...this.ctx.storage.sql.exec(
				`SELECT COUNT(*) as total FROM emails ${where}`,
				...params,
			),
		][0] as { total: number } | undefined;

		return row?.total ?? 0;
	}

	// ── Threaded queries (raw SQL — too complex for Drizzle's builder) ──

	async getThreadedEmails(options: GetEmailsOptions = {}) {
		const {
			folder,
			page = 1,
			limit: rawLimit = 25,
		} = options;
		const limit = Math.min(Math.max(rawLimit, 1), 100);

		if (!folder) {
			// Fallback to regular getEmails if no folder specified
			return this.getEmails(options);
		}

		const offset = (page - 1) * limit;

		// Thread grouping strategy:
		// For DRAFT folder: group by in_reply_to (the email being replied to).
		//   This ensures reply-drafts to different emails stay separate, even if
		//   they share a thread_id or subject. New drafts (no in_reply_to) each
		//   get their own group via their unique id.
		// For other folders:
		//   1. Primary: group by thread_id (from email threading headers)
		//   2. Fallback: group by normalized subject (strips Re:/Fwd:/FW: prefixes)
		//      for legacy emails that lack threading headers (thread_id IS NULL).
		const isDraftFolder = folder === Folders.DRAFT;

		if (isDraftFolder) {
			const result = this.ctx.storage.sql.exec<ThreadedEmailRow>(
				`WITH
				folder_emails AS (
					SELECT *,
						COALESCE(in_reply_to, id) as draft_group_key
					FROM emails
					WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
				),
				draft_stats AS (
					SELECT
						draft_group_key,
						COUNT(*) as thread_count,
						SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END) as thread_unread_count,
						GROUP_CONCAT(DISTINCT sender) as participants
					FROM folder_emails
					GROUP BY draft_group_key
				),
				latest_per_group AS (
					SELECT
						fe.*,
						ROW_NUMBER() OVER (
							PARTITION BY fe.draft_group_key
							ORDER BY fe.date DESC
						) as rn
					FROM folder_emails fe
				)
				SELECT
					lp.id, lp.subject, lp.sender, lp.recipient, lp.date,
					lp.read, lp.starred, lp.thread_id, lp.folder_id,
					lp.in_reply_to, lp.email_references,
					SUBSTR(lp.body, 1, 300) as snippet,
					ds.thread_count, ds.thread_unread_count, ds.participants
				FROM latest_per_group lp
				JOIN draft_stats ds ON lp.draft_group_key = ds.draft_group_key
				WHERE lp.rn = 1
				ORDER BY lp.date DESC
				LIMIT ?2 OFFSET ?3`,
				folder, limit, offset
			);

			const rows = result.toArray();
			return rows.map((row) => ({
				...row,
				read: !!row.read,
				starred: !!row.starred,
				thread_count: row.thread_count || 1,
				thread_unread_count: row.thread_unread_count || 0,
				participants: row.participants || row.sender,
			}));
		}

		// Non-draft folders: full threading logic
		const result = this.ctx.storage.sql.exec<ThreadedEmailRow>(
			`WITH
			folder_emails AS (
				SELECT *,
					COALESCE(thread_id, id) as raw_thread_id,
					${NORMALIZED_SUBJECT_SQL} as normalized_subject
				FROM emails
				WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
			),
			thread_to_conversation AS (
				SELECT
					raw_thread_id,
					normalized_subject,
					CASE
						WHEN thread_id IS NOT NULL THEN raw_thread_id
						WHEN normalized_subject != '' THEN MIN(raw_thread_id) OVER (PARTITION BY normalized_subject)
						ELSE raw_thread_id
					END as conversation_id
				FROM folder_emails
				GROUP BY raw_thread_id, normalized_subject, thread_id
			),
			all_emails_with_conversation AS (
				SELECT
					e.*,
					COALESCE(tc.conversation_id, COALESCE(e.thread_id, e.id)) as conversation_id
				FROM emails e
				LEFT JOIN thread_to_conversation tc
					ON COALESCE(e.thread_id, e.id) = tc.raw_thread_id
			),
			conversation_stats AS (
				SELECT
					conversation_id,
					COUNT(*) as thread_count,
					SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END) as thread_unread_count,
					SUM(CASE WHEN read = 1 THEN 1 ELSE 0 END) as thread_read_count,
					GROUP_CONCAT(DISTINCT sender) as participants,
					SUM(CASE WHEN folder_id = (SELECT id FROM folders WHERE name = 'draft' LIMIT 1) THEN 1 ELSE 0 END) as has_draft
				FROM all_emails_with_conversation
				WHERE conversation_id IN (
					SELECT DISTINCT conversation_id FROM all_emails_with_conversation
					WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
				)
				GROUP BY conversation_id
			),
			latest_message_per_conversation AS (
				SELECT
					conversation_id,
					folder_id,
					ROW_NUMBER() OVER (PARTITION BY conversation_id ORDER BY date DESC) as rn
				FROM all_emails_with_conversation
			),
			latest_in_folder AS (
				SELECT
					fe.*,
					COALESCE(tc.conversation_id, fe.raw_thread_id) as conversation_id,
					ROW_NUMBER() OVER (
						PARTITION BY COALESCE(tc.conversation_id, fe.raw_thread_id)
						ORDER BY fe.date DESC
					) as rn
				FROM folder_emails fe
				LEFT JOIN thread_to_conversation tc
					ON fe.raw_thread_id = tc.raw_thread_id
			)
			SELECT
				lif.id, lif.subject, lif.sender, lif.recipient, lif.date,
				lif.read, lif.starred, lif.thread_id, lif.folder_id,
				lif.in_reply_to, lif.email_references,
				SUBSTR(lif.body, 1, 300) as snippet,
				cs.thread_count, cs.thread_unread_count, cs.participants,
				CASE WHEN lmc.folder_id != (SELECT id FROM folders WHERE name = 'sent' LIMIT 1)
					AND lmc.folder_id != (SELECT id FROM folders WHERE name = 'draft' LIMIT 1)
					AND cs.thread_read_count > 0
					THEN 1 ELSE 0 END as needs_reply,
				CASE WHEN cs.has_draft > 0 THEN 1 ELSE 0 END as has_draft
			FROM latest_in_folder lif
			JOIN conversation_stats cs ON lif.conversation_id = cs.conversation_id
			LEFT JOIN latest_message_per_conversation lmc
				ON lmc.conversation_id = lif.conversation_id AND lmc.rn = 1
			WHERE lif.rn = 1
			ORDER BY lif.date DESC
			LIMIT ?2 OFFSET ?3`,
			folder, limit, offset
		);

		const rows = result.toArray();
		return rows.map((row) => ({
			...row,
			read: !!row.read,
			starred: !!row.starred,
			thread_count: row.thread_count || 1,
			thread_unread_count: row.thread_unread_count || 0,
			participants: row.participants || row.sender,
			needs_reply: !!row.needs_reply,
			has_draft: !!row.has_draft,
		}));
	}

	/**
	 * Count threaded conversations in a folder (for pagination).
	 * Returns the number of conversation groups, not individual emails.
	 */
	async countThreadedEmails(folder: string) {
		const isDraftFolder = folder === Folders.DRAFT;

		if (isDraftFolder) {
			const row = [
				...this.ctx.storage.sql.exec(
					`SELECT COUNT(DISTINCT COALESCE(in_reply_to, id)) as total
					 FROM emails
					 WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)`,
					folder,
				),
			][0] as { total: number } | undefined;
			return row?.total ?? 0;
		}

		const row = [
			...this.ctx.storage.sql.exec(
				`WITH
				folder_emails AS (
					SELECT
						COALESCE(thread_id, id) as raw_thread_id,
						thread_id,
					${NORMALIZED_SUBJECT_SQL} as normalized_subject
					FROM emails
					WHERE folder_id = (SELECT id FROM folders WHERE name = ?1 OR id = ?1 LIMIT 1)
				),
				thread_to_conversation AS (
					SELECT
						raw_thread_id,
						CASE
							WHEN thread_id IS NOT NULL THEN raw_thread_id
							WHEN normalized_subject != '' THEN MIN(raw_thread_id) OVER (PARTITION BY normalized_subject)
							ELSE raw_thread_id
						END as conversation_id
					FROM folder_emails
					GROUP BY raw_thread_id, normalized_subject, thread_id
				)
				SELECT COUNT(DISTINCT conversation_id) as total
				FROM thread_to_conversation`,
				folder,
			),
		][0] as { total: number } | undefined;
		return row?.total ?? 0;
	}

	// ── Single email operations (Drizzle) ──────────────────────────

	async getEmail(id: string) {
		const email = this.db
			.select()
			.from(schema.emails)
			.where(eq(schema.emails.id, id))
			.get();

		if (!email) return null;

		const emailAttachments = this.db
			.select()
			.from(schema.attachments)
			.where(eq(schema.attachments.email_id, id))
			.all();

		return {
			...email,
			read: !!email.read,
			starred: !!email.starred,
			attachments: emailAttachments,
		};
	}

	/**
	 * Fetch all emails in a thread with full bodies and attachments in
	 * two queries (one for emails, one for attachments) instead of
	 * N+1 individual getEmail calls.
	 */
	async getThreadEmails(threadId: string) {
		const emailRows = this.ctx.storage.sql.exec<EmailSqlRow>(
				`SELECT * FROM emails WHERE thread_id = ?1 ORDER BY date ASC`,
				threadId,
			).toArray();

		if (emailRows.length === 0) return [];

		const emailIds = emailRows.map((e) => e.id as string);

		// Batch-fetch all attachments for the thread in a single query
		const placeholders = emailIds.map((_, i) => `?${i + 1}`).join(",");
		const attachmentRows = this.ctx.storage.sql.exec<AttachmentSqlRow>(
				`SELECT * FROM attachments WHERE email_id IN (${placeholders})`,
				...emailIds,
			).toArray();

		// Group attachments by email_id
		const attachmentsByEmail = new Map<string, AttachmentSqlRow[]>();
		for (const att of attachmentRows) {
			const list = attachmentsByEmail.get(att.email_id) || [];
			list.push(att);
			attachmentsByEmail.set(att.email_id, list);
		}

		return emailRows.map((email) => ({
			...email,
			read: !!email.read,
			starred: !!email.starred,
			attachments: attachmentsByEmail.get(email.id) || [],
		}));
	}

	async updateEmail(
		id: string,
		{ read, starred }: { read?: boolean; starred?: boolean },
	) {
		const data: { read?: number; starred?: number } = {};
		if (read !== undefined) {
			data.read = read ? 1 : 0;
		}
		if (starred !== undefined) {
			data.starred = starred ? 1 : 0;
		}

		if (Object.keys(data).length === 0) {
			return this.getEmail(id);
		}

		this.db
			.update(schema.emails)
			.set(data)
			.where(eq(schema.emails.id, id))
			.run();

		return this.getEmail(id);
	}

	async markThreadRead(threadId: string) {
		this.ctx.storage.sql.exec(
			`UPDATE emails SET read = 1 WHERE thread_id = ? AND read = 0`,
			threadId,
		);
		return { threadId, markedRead: true };
	}

	async deleteEmail(id: string) {
		const email = this.db
			.select({ id: schema.emails.id })
			.from(schema.emails)
			.where(eq(schema.emails.id, id))
			.get();

		if (!email) return null;

		const emailAttachments = this.db
			.select({
				id: schema.attachments.id,
				email_id: schema.attachments.email_id,
				filename: schema.attachments.filename,
				object_key: schema.attachments.object_key,
			})
			.from(schema.attachments)
			.where(eq(schema.attachments.email_id, id))
			.all();

		// Delete external blobs before removing the database record. If R2 is
		// unavailable, the email remains retryable and its attachment metadata
		// is not lost.
		if (emailAttachments.length > 0) {
			await deleteAttachmentObjects(this.env.BUCKET, emailAttachments);
		}

		this.ctx.storage.transactionSync(() => {
			this.db
				.delete(schema.emails)
				.where(eq(schema.emails.id, id))
				.run();
			this.db
				.delete(schema.agentJobs)
				.where(eq(schema.agentJobs.email_id, id))
				.run();
		});

		return emailAttachments;
	}

	async getAttachment(id: string) {
		return (
			this.db
				.select()
				.from(schema.attachments)
				.where(eq(schema.attachments.id, id))
				.get() ?? null
		);
	}

	// ── Folders (Drizzle) ──────────────────────────────────────────

	async getFolders() {
		const result = this.db
			.select({
				id: schema.folders.id,
				name: schema.folders.name,
				unreadCount: sql<number>`COALESCE(SUM(CASE WHEN ${schema.emails.read} = 0 THEN 1 ELSE 0 END), 0)`.mapWith(Number),
			})
			.from(schema.folders)
			.leftJoin(schema.emails, eq(schema.emails.folder_id, schema.folders.id))
			.groupBy(schema.folders.id, schema.folders.name)
			.all();
		return result;
	}

	async createFolder(id: string, name: string, is_deletable: number = 1) {
		try {
			const result = this.db
				.insert(schema.folders)
				.values({ id, name, is_deletable })
				.returning({ id: schema.folders.id, name: schema.folders.name })
				.get();
			return { ...result, unreadCount: 0 };
		} catch (e: unknown) {
			if (e instanceof Error && e.message.includes("UNIQUE constraint failed")) {
				return null;
			}
			throw e;
		}
	}

	async updateFolder(id: string, name: string) {
		const result = this.db
			.update(schema.folders)
			.set({ name })
			.where(eq(schema.folders.id, id))
			.returning({ id: schema.folders.id, name: schema.folders.name })
			.get();
		return result;
	}

	async deleteFolder(id: string) {
		const folder = this.db
			.select({ is_deletable: schema.folders.is_deletable })
			.from(schema.folders)
			.where(eq(schema.folders.id, id))
			.get();

		if (!folder || folder.is_deletable === 0) {
			return false;
		}

		this.db
			.delete(schema.folders)
			.where(eq(schema.folders.id, id))
			.run();

		return true;
	}

	async moveEmail(id: string, folderId: string) {
		const folder = this.db
			.select({ id: schema.folders.id })
			.from(schema.folders)
			.where(eq(schema.folders.id, folderId))
			.get();

		if (!folder) return false;

		this.db
			.update(schema.emails)
			.set({ folder_id: folderId })
			.where(eq(schema.emails.id, id))
			.run();

		return true;
	}

	// ── Search (raw SQL — dynamic condition builder) ───────────────

	/**
	 * Build WHERE conditions and params for search queries.
	 * Shared between searchEmails and countSearchResults.
	 */
	#buildSearchConditions(
		options: SearchFilterOptions,
		tableAlias = "",
	): { conditions: string[]; params: (string | number)[] } {
		const { query, folder, from, to, subject, date_start, date_end, is_read, is_starred, has_attachment } = options;
		const prefix = tableAlias ? `${tableAlias}.` : "";
		const conditions: string[] = [];
		const params: (string | number)[] = [];
		let paramIdx = 0;

		const addParam = (value: string | number) => {
			paramIdx++;
			params.push(value);
			return `?${paramIdx}`;
		};

		if (query) {
			const p1 = addParam(`%${query}%`);
			const p2 = addParam(`%${query}%`);
			const p3 = addParam(`%${query}%`);
			const p4 = addParam(`%${query}%`);
			conditions.push(`(${prefix}subject LIKE ${p1} OR ${prefix}body LIKE ${p2} OR ${prefix}sender LIKE ${p3} OR ${prefix}recipient LIKE ${p4} OR ${prefix}cc LIKE ${p4} OR ${prefix}bcc LIKE ${p4})`);
		}
		if (folder) {
			const p = addParam(folder);
			conditions.push(`${prefix}folder_id = (SELECT id FROM folders WHERE name = ${p} OR id = ${p} LIMIT 1)`);
		}
		if (from) { const p = addParam(`%${from}%`); conditions.push(`${prefix}sender LIKE ${p}`); }
		if (to) { const p = addParam(`%${to}%`); conditions.push(`(${prefix}recipient LIKE ${p} OR ${prefix}cc LIKE ${p} OR ${prefix}bcc LIKE ${p})`); }
		if (subject) { const p = addParam(`%${subject}%`); conditions.push(`${prefix}subject LIKE ${p}`); }
		if (date_start) { const p = addParam(date_start); conditions.push(`${prefix}date >= ${p}`); }
		if (date_end) { const p = addParam(date_end); conditions.push(`${prefix}date <= ${p}`); }
		if (is_read !== undefined) { const p = addParam(is_read ? 1 : 0); conditions.push(`${prefix}read = ${p}`); }
		if (is_starred !== undefined) { const p = addParam(is_starred ? 1 : 0); conditions.push(`${prefix}starred = ${p}`); }
		if (has_attachment) { conditions.push(`${prefix}id IN (SELECT DISTINCT email_id FROM attachments)`); }

		return { conditions, params };
	}

	async searchEmails(options: SearchFilterOptions & { page?: number; limit?: number }) {
		const { page = 1, limit: rawLimit = 25 } = options;
		const limit = Math.min(Math.max(rawLimit, 1), 100);
		const { conditions, params } = this.#buildSearchConditions(options, "e");

		const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
		const offset = (page - 1) * limit;

		const query = `
			SELECT e.id, e.subject, e.sender, e.recipient, e.cc, e.bcc, e.date,
				e.read, e.starred, e.in_reply_to, e.email_references,
				e.thread_id, e.folder_id,
				SUBSTR(e.body, 1, 300) as snippet,
				f.name as folder_name
			FROM emails e
			LEFT JOIN folders f ON e.folder_id = f.id
			${where}
			ORDER BY e.date DESC LIMIT ?${params.length + 1} OFFSET ?${params.length + 2}`;
		params.push(limit, offset);

		const result = this.ctx.storage.sql.exec<SqlRow>(query, ...params);
		return result.toArray().map((row) => ({
			...row,
			read: !!row.read,
			starred: !!row.starred,
		}));
	}

	/**
	 * Count total search results matching the given filters (for pagination).
	 */
	async countSearchResults(options: SearchFilterOptions) {
		const { conditions, params } = this.#buildSearchConditions(options);

		const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
		const query = `SELECT COUNT(*) as total FROM emails ${where}`;

		const row = [...this.ctx.storage.sql.exec(query, ...params)][0] as
			| { total: number }
			| undefined;
		return row?.total ?? 0;
	}

	// ── Threading helpers (raw SQL) ────────────────────────────────

	async findThreadBySubject(subject: string, senderAddress?: string): Promise<string | null> {
		const normalized = subject
			.replace(/^(?:(?:re|fwd?|fw|aw|wg|r[eé]f|sv)\s*:\s*)+/i, "")
			.trim()
			.toLowerCase();

		if (!normalized) return null;

		const result = this.ctx.storage.sql.exec<ThreadCandidateRow>(
			`SELECT thread_id, subject,
			        GROUP_CONCAT(DISTINCT LOWER(sender)) as senders,
			        GROUP_CONCAT(DISTINCT LOWER(recipient)) as recipients
			 FROM emails
			 WHERE thread_id IS NOT NULL
			   AND thread_id != id
			   AND date >= datetime('now', '-7 days')
			 GROUP BY thread_id
			 ORDER BY MAX(date) DESC
			 LIMIT 50`,
		);

		const normalizedSender = senderAddress?.toLowerCase().trim();

		for (const row of result) {
			const rowSubject = String(row.subject || "")
				.replace(/^(?:(?:re|fwd?|fw|aw|wg|r[eé]f|sv)\s*:\s*)+/i, "")
				.trim()
				.toLowerCase();
			if (rowSubject !== normalized) continue;

			if (normalizedSender) {
				const threadSenders = String(row.senders || "");
				const threadRecipients = String(row.recipients || "");
				const allParticipants = `${threadSenders},${threadRecipients}`
					.split(",")
					.map((participant) => participant.trim())
					.filter(Boolean);
				if (!allParticipants.includes(normalizedSender)) {
					continue;
				}
			}

			return String(row.thread_id);
		}
		return null;
	}

	// ── Rate limiting (raw SQL) ────────────────────────────────────

	/**
	 * Check if the mailbox has exceeded the send rate limit.
	 * Limits: 20 emails per hour, 100 per day per mailbox.
	 * Returns null if under limit, or an error message string if exceeded.
	 */
	async checkSendRateLimit(): Promise<string | null> {
		const now = Date.now();
		return this.ctx.storage.transactionSync(() => {
			const hour = this.db.select().from(schema.rateLimits).where(eq(schema.rateLimits.key, "send:hour")).get();
			const day = this.db.select().from(schema.rateLimits).where(eq(schema.rateLimits.key, "send:day")).get();
			const hourActive = hour && now - hour.window_start < 60 * 60 * 1000;
			const dayActive = day && now - day.window_start < 24 * 60 * 60 * 1000;
			if (hourActive && hour.count >= 20) return "Rate limit exceeded: max 20 emails per hour per mailbox";
			if (dayActive && day.count >= 100) return "Rate limit exceeded: max 100 emails per day per mailbox";

			const increment = (key: string, row: typeof hour, active: boolean) => {
				const count = active && row ? row.count + 1 : 1;
				this.db.insert(schema.rateLimits)
					.values({ key, window_start: now, count })
					.onConflictDoUpdate({
						target: schema.rateLimits.key,
						set: { window_start: now, count },
					})
					.run();
			};
			increment("send:hour", hour, Boolean(hourActive));
			increment("send:day", day, Boolean(dayActive));
			return null;
		});
	}

	/** Atomically consume a mailbox-scoped sliding window counter. */
	async checkRateLimit(kind: string, limit: number, windowSeconds: number): Promise<boolean> {
		const now = Date.now();
		const windowMs = windowSeconds * 1000;
		return this.ctx.storage.transactionSync(() => {
			const row = this.db
				.select()
				.from(schema.rateLimits)
				.where(eq(schema.rateLimits.key, kind))
				.get();
			if (!row || now - row.window_start >= windowMs) {
				this.db
					.insert(schema.rateLimits)
					.values({ key: kind, window_start: now, count: 1 })
					.onConflictDoUpdate({
						target: schema.rateLimits.key,
						set: { window_start: now, count: 1 },
					})
					.run();
				return true;
			}
			if (row.count >= limit) return false;
			this.db
				.update(schema.rateLimits)
				.set({ count: row.count + 1 })
				.where(eq(schema.rateLimits.key, kind))
				.run();
			return true;
		});
	}

	async claimAutoDraftJob(emailId: string, mailboxId: string, maxAttempts = 5): Promise<"claimed" | "pending" | "done" | "failed"> {
		return this.ctx.storage.transactionSync(() => {
			const now = Date.now();
			const row = this.db.select().from(schema.agentJobs).where(eq(schema.agentJobs.email_id, emailId)).get();
			if (!row) {
				this.db.insert(schema.agentJobs).values({ email_id: emailId, mailbox_id: mailboxId, status: "processing", attempts: 1, lease_until: now + 10 * 60 * 1000, updated_at: now }).run();
				return "claimed";
			}
			if (row.status === "done") return "done";
			if (row.status === "failed" && row.attempts >= maxAttempts) return "failed";
			if (row.status === "processing" && row.lease_until && row.lease_until > now) return "pending";
			if (row.attempts >= maxAttempts) {
				this.db.update(schema.agentJobs).set({ status: "failed", updated_at: now }).where(eq(schema.agentJobs.email_id, emailId)).run();
				return "failed";
			}
			this.db.update(schema.agentJobs).set({ status: "processing", attempts: row.attempts + 1, lease_until: now + 10 * 60 * 1000, updated_at: now }).where(eq(schema.agentJobs.email_id, emailId)).run();
			return "claimed";
		});
	}

	async completeAutoDraftJob(emailId: string) {
		this.db.update(schema.agentJobs).set({ status: "done", lease_until: null, updated_at: Date.now() }).where(eq(schema.agentJobs.email_id, emailId)).run();
	}

	async failAutoDraftJob(emailId: string, error: string, maxAttempts = 5): Promise<{ retry: boolean }> {
		let shouldScheduleRetry = false;
		const result = this.ctx.storage.transactionSync(() => {
			const row = this.db.select({ attempts: schema.agentJobs.attempts }).from(schema.agentJobs).where(eq(schema.agentJobs.email_id, emailId)).get();
			if (!row) return { retry: false };
			const retry = row.attempts < maxAttempts;
			shouldScheduleRetry = retry;
			this.db.update(schema.agentJobs).set({ status: retry ? "queued" : "failed", lease_until: null, updated_at: Date.now() }).where(eq(schema.agentJobs.email_id, emailId)).run();
			if (!retry) console.error(JSON.stringify({ event: "auto_draft_failed", emailId, error: error.slice(0, 500) }));
			return { retry };
		});
		if (shouldScheduleRetry) await this.ctx.storage.setAlarm(Date.now() + 10_000);
		return result;
	}

	/** Persist a fallback auto-draft job when Queue submission itself fails. */
	async scheduleAutoDraftRetry(emailId: string, mailboxId: string, delayMs = 1_000) {
		const now = Date.now();
		const active = this.db
			.select({ status: schema.agentJobs.status, leaseUntil: schema.agentJobs.lease_until })
			.from(schema.agentJobs)
			.where(eq(schema.agentJobs.email_id, emailId))
			.get();
		if (!(active?.status === "processing" && active.leaseUntil && active.leaseUntil > now)) {
			this.db.insert(schema.agentJobs).values({ email_id: emailId, mailbox_id: mailboxId, status: "queued", attempts: 0, lease_until: null, updated_at: now })
				.onConflictDoUpdate({
					target: schema.agentJobs.email_id,
					set: { status: "queued", lease_until: null, updated_at: now },
				})
				.run();
		}
		await this.ctx.storage.setAlarm(now + delayMs);
	}

	// ── Mailbox lifecycle ─────────────────────────────────────────────

	/**
	 * Return all attachment records before mailbox deletion so the route
	 * handler can remove R2 blobs before destroying this DO's storage.
	 */
	async listAttachmentKeys(): Promise<{ emailId: string; attachmentId: string; filename: string; objectKey: string | null }[]> {
		const attachments = this.db
			.select({
				email_id: schema.attachments.email_id,
				id: schema.attachments.id,
				filename: schema.attachments.filename,
				object_key: schema.attachments.object_key,
			})
			.from(schema.attachments)
			.all();

		return attachments.map((a) => ({
			emailId: a.email_id,
			attachmentId: a.id,
			filename: a.filename,
			objectKey: a.object_key,
		}));
	}

	async destroy(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}

	// ── Email creation (Drizzle) ───────────────────────────────────

	async createEmail(
		folder: string,
		email: EmailData,
		attachments: AttachmentData[],
	) {
		this.ctx.storage.transactionSync(() => this.insertEmail(folder, email, attachments));
	}

	async createInboundEmail(
		email: EmailData,
		attachments: AttachmentData[],
	): Promise<{ duplicate: boolean; id: string }> {
		if (email.inbound_key) {
			const existing = this.db
				.select({ id: schema.emails.id })
				.from(schema.emails)
				.where(eq(schema.emails.inbound_key, email.inbound_key))
				.get();
			if (existing) return { duplicate: true, id: existing.id };
		}
		this.ctx.storage.transactionSync(() => this.insertEmail(Folders.INBOX, email, attachments));
		return { duplicate: false, id: email.id };
	}

	async hasInboundEmail(inboundKey: string): Promise<boolean> {
		return Boolean(this.db
			.select({ id: schema.emails.id })
			.from(schema.emails)
			.where(eq(schema.emails.inbound_key, inboundKey))
			.get());
	}

	async getOutboundByIdempotencyKey(idempotencyKey: string) {
		return this.db
			.select({
				operationId: schema.outbox.operation_id,
				emailId: schema.outbox.email_id,
				payloadHash: schema.outbox.payload_hash,
				status: schema.outbox.status,
			})
			.from(schema.outbox)
			.where(eq(schema.outbox.idempotency_key, idempotencyKey))
			.get() ?? null;
	}

	async createOutboundEmail(
		mailboxId: string,
		email: EmailData,
		attachments: AttachmentData[],
		operationId: string,
		idempotencyKey: string,
		payloadHash: string,
		sourceDraftId?: string | null,
	): Promise<
		| { ok: true; created: boolean; operationId: string; emailId: string; status: string }
		| { ok: false; reason: "idempotency_conflict" | "source_draft_not_found" | "source_not_draft" }
	> {
		const existing = this.db
			.select({
				operationId: schema.outbox.operation_id,
				emailId: schema.outbox.email_id,
				payloadHash: schema.outbox.payload_hash,
				status: schema.outbox.status,
			})
			.from(schema.outbox)
			.where(eq(schema.outbox.idempotency_key, idempotencyKey))
			.get();
		if (existing) {
			if (existing.payloadHash !== payloadHash) return { ok: false, reason: "idempotency_conflict" };
			return { ok: true, created: false, operationId: existing.operationId, emailId: existing.emailId, status: existing.status };
		}

		const now = Date.now();
		let result: { ok: true; created: boolean; operationId: string; emailId: string; status: string } | { ok: false; reason: "source_draft_not_found" | "source_not_draft" } = {
			ok: true,
			created: true,
			operationId,
			emailId: email.id,
			status: "queued",
		};
		this.ctx.storage.transactionSync(() => {
			if (sourceDraftId) {
				const source = this.db
					.select({ folderId: schema.emails.folder_id })
					.from(schema.emails)
					.where(eq(schema.emails.id, sourceDraftId))
					.get();
				if (!source) {
					result = { ok: false, reason: "source_draft_not_found" };
					return;
				}
				if (source.folderId !== Folders.DRAFT) {
					result = { ok: false, reason: "source_not_draft" };
					return;
				}
			}

			this.insertEmail(Folders.SENT, {
				...email,
				delivery_status: "queued",
				delivery_operation_id: operationId,
				source_draft_id: sourceDraftId ?? null,
			}, attachments);
			this.db.insert(schema.outbox).values({
				operation_id: operationId,
				mailbox_id: mailboxId,
				email_id: email.id,
				idempotency_key: idempotencyKey,
				payload_hash: payloadHash,
				status: "queued",
				attempts: 0,
				lease_until: null,
				next_attempt_at: null,
				provider_message_id: null,
				last_error: null,
				created_at: now,
				updated_at: now,
			}).run();
		});
		return result;
	}

	async getOutboundStatus(operationId: string) {
		return this.db
			.select({
				operationId: schema.outbox.operation_id,
				emailId: schema.outbox.email_id,
				status: schema.outbox.status,
				attempts: schema.outbox.attempts,
				providerMessageId: schema.outbox.provider_message_id,
				lastError: schema.outbox.last_error,
				updatedAt: schema.outbox.updated_at,
			})
			.from(schema.outbox)
			.where(eq(schema.outbox.operation_id, operationId))
			.get() ?? null;
	}

	async claimOutboundDelivery(operationId: string, maxAttempts = 5): Promise<OutboxClaimResult> {
		return this.ctx.storage.transactionSync(() => {
			const row = this.db
				.select({
					status: schema.outbox.status,
					emailId: schema.outbox.email_id,
					attempts: schema.outbox.attempts,
					leaseUntil: schema.outbox.lease_until,
				})
				.from(schema.outbox)
				.where(eq(schema.outbox.operation_id, operationId))
				.get();
			if (!row) return { status: "missing", operationId };
			if (row.status === "sent") return { status: "sent", operationId };
			if (row.status === "failed") return { status: "failed", operationId };
			const now = Date.now();
			if (row.leaseUntil && row.leaseUntil > now) return { status: "pending", operationId };
			if (row.attempts >= maxAttempts) {
				this.db.update(schema.outbox).set({ status: "failed", updated_at: now, last_error: "Maximum delivery attempts exceeded" }).where(eq(schema.outbox.operation_id, operationId)).run();
				this.db.update(schema.emails).set({ delivery_status: "failed" }).where(eq(schema.emails.id, row.emailId)).run();
				return { status: "failed", operationId };
			}
			const attempts = row.attempts + 1;
			this.db.update(schema.outbox).set({
				status: "processing",
				attempts,
				lease_until: now + 5 * 60 * 1000,
				updated_at: now,
				next_attempt_at: null,
			}).where(eq(schema.outbox.operation_id, operationId)).run();
			return { status: "claimed", operationId, emailId: row.emailId, attempts };
		});
	}

	async completeOutboundDelivery(operationId: string, providerMessageId: string): Promise<{ ok: boolean; draftAttachments: AttachmentData[] }> {
		return this.ctx.storage.transactionSync(() => {
			const row = this.db
				.select({ emailId: schema.outbox.email_id, status: schema.outbox.status })
				.from(schema.outbox)
				.where(eq(schema.outbox.operation_id, operationId))
				.get();
			if (!row) return { ok: false, draftAttachments: [] };
			if (row.status === "sent") return { ok: true, draftAttachments: [] };
			const sent = this.db
				.select({ sourceDraftId: schema.emails.source_draft_id })
				.from(schema.emails)
				.where(eq(schema.emails.id, row.emailId))
				.get();
			let draftAttachments: AttachmentData[] = [];
			if (sent?.sourceDraftId) {
				const draft = this.db
					.select({ folderId: schema.emails.folder_id })
					.from(schema.emails)
					.where(eq(schema.emails.id, sent.sourceDraftId))
					.get();
				if (draft?.folderId === Folders.DRAFT) {
					draftAttachments = this.db
						.select()
						.from(schema.attachments)
						.where(eq(schema.attachments.email_id, sent.sourceDraftId))
						.all() as AttachmentData[];
					this.db.delete(schema.emails).where(eq(schema.emails.id, sent.sourceDraftId)).run();
				}
			}
			const now = Date.now();
			this.db.update(schema.outbox).set({ status: "sent", provider_message_id: providerMessageId, lease_until: null, updated_at: now, last_error: null }).where(eq(schema.outbox.operation_id, operationId)).run();
			this.db.update(schema.emails).set({ delivery_status: "sent" }).where(eq(schema.emails.id, row.emailId)).run();
			return { ok: true, draftAttachments };
		});
	}

	async failOutboundDelivery(operationId: string, error: string, maxAttempts = 5): Promise<{ retry: boolean; attempts: number }> {
		let retryAt: number | null = null;
		const result = this.ctx.storage.transactionSync(() => {
			const row = this.db
				.select({ attempts: schema.outbox.attempts, emailId: schema.outbox.email_id })
				.from(schema.outbox)
				.where(eq(schema.outbox.operation_id, operationId))
				.get();
			if (!row) return { retry: false, attempts: 0 };
			const retry = row.attempts < maxAttempts;
			const now = Date.now();
			retryAt = retry ? now + Math.min(60_000, 2 ** row.attempts * 1_000) : null;
			this.db.update(schema.outbox).set({
				status: retry ? "queued" : "failed",
				lease_until: null,
				next_attempt_at: retryAt,
				last_error: error.slice(0, 1_000),
				updated_at: now,
			}).where(eq(schema.outbox.operation_id, operationId)).run();
			this.db.update(schema.emails).set({ delivery_status: retry ? "queued" : "failed" }).where(eq(schema.emails.id, row.emailId)).run();
			return { retry, attempts: row.attempts };
		});
		if (retryAt !== null) await this.ctx.storage.setAlarm(retryAt);
		return result;
	}

	async scheduleOutboundRetry(operationId: string, delayMs = 1_000) {
		const nextAttemptAt = Date.now() + delayMs;
		this.db.update(schema.outbox).set({ status: "queued", next_attempt_at: nextAttemptAt, updated_at: Date.now() }).where(eq(schema.outbox.operation_id, operationId)).run();
		await this.ctx.storage.setAlarm(nextAttemptAt);
	}

	async alarm() {
		const rows = [...this.ctx.storage.sql.exec(
			`SELECT operation_id, mailbox_id FROM outbox WHERE status = 'queued' AND (next_attempt_at IS NULL OR next_attempt_at <= ?1) LIMIT 20`,
			Date.now(),
		)] as Array<{ operation_id: string; mailbox_id: string }>;
		for (const row of rows) {
			try {
				await this.env.OUTBOUND_QUEUE.send({ mailboxId: row.mailbox_id, operationId: row.operation_id });
				this.ctx.storage.sql.exec(`UPDATE outbox SET next_attempt_at = NULL, updated_at = ?1 WHERE operation_id = ?2`, Date.now(), row.operation_id);
			} catch {
				await this.ctx.storage.setAlarm(Date.now() + 30_000);
			}
		}
		if (rows.length >= 20) await this.ctx.storage.setAlarm(Date.now() + 1_000);

		const autoDraftRows = [...this.ctx.storage.sql.exec(
			`SELECT j.email_id, j.mailbox_id, e.sender, e.subject, e.thread_id
			 FROM agent_jobs j JOIN emails e ON e.id = j.email_id
			 WHERE j.status = 'queued' ORDER BY j.updated_at ASC LIMIT 20`,
		)] as Array<{ email_id: string; mailbox_id: string; sender: string | null; subject: string | null; thread_id: string | null }>;
		for (const row of autoDraftRows) {
			try {
				await this.env.AUTO_DRAFT_QUEUE.send({
					mailboxId: row.mailbox_id,
					emailId: row.email_id,
					sender: row.sender || "",
					subject: row.subject || "",
					threadId: row.thread_id || row.email_id,
				});
			} catch {
				await this.ctx.storage.setAlarm(Date.now() + 30_000);
			}
		}
		if (autoDraftRows.length >= 20) await this.ctx.storage.setAlarm(Date.now() + 1_000);
	}

	/**
	 * Atomically replace an existing draft with new content.
	 * Runs delete + insert in a single DO method call — no async between
	 * the two operations — so a Worker crash cannot leave a gap.
	 */
	async replaceDraft(
		oldDraftId: string | null,
		email: EmailData,
		attachments: AttachmentData[],
	): Promise<DraftReplacementResult> {
		let result: DraftReplacementResult = { ok: true, id: email.id, date: email.date };
		this.ctx.storage.transactionSync(() => {
			if (oldDraftId) {
				const existing = this.db
					.select({ folderId: schema.emails.folder_id })
					.from(schema.emails)
					.where(eq(schema.emails.id, oldDraftId))
					.get();
				if (!existing) {
					result = { ok: false, reason: "not_found" };
					return;
				}
				if (existing.folderId !== Folders.DRAFT) {
					result = { ok: false, reason: "not_draft" };
					return;
				}
				this.db.delete(schema.emails).where(eq(schema.emails.id, oldDraftId)).run();
				this.insertEmail(Folders.DRAFT, { ...email, id: oldDraftId }, attachments);
				result = { ok: true, id: oldDraftId, date: email.date };
				return;
			}
			this.insertEmail(Folders.DRAFT, email, attachments);
		});
		return result;
	}

	private insertEmail(
		folder: string,
		email: EmailData,
		attachments: AttachmentData[],
	) {
		const folderRow = this.db
			.select({ id: schema.folders.id })
			.from(schema.folders)
			.where(or(eq(schema.folders.id, folder), eq(schema.folders.name, folder)))
			.limit(1)
			.get();

		if (!folderRow) {
			throw new Error(
				`createEmail: folder "${folder}" not found. ` +
					"Ensure the folder exists before inserting an email.",
			);
		}

		const folderId = folderRow.id;
		const isSent = folderId === Folders.SENT;

		// Sent emails are always read; the sender already knows what they wrote.
		this.db
			.insert(schema.emails)
			.values({
				id: email.id,
				folder_id: folderId,
				subject: email.subject,
				sender: email.sender,
				recipient: email.recipient,
				cc: email.cc ?? null,
				bcc: email.bcc ?? null,
				date: email.date,
				read: isSent ? 1 : (email.read ? 1 : 0),
				starred: email.starred ? 1 : 0,
				body: email.body,
				body_format: email.body_format === "text" ? "text" : "html",
				in_reply_to: email.in_reply_to ?? null,
				email_references: email.email_references ?? null,
				thread_id: email.thread_id ?? null,
				message_id: email.message_id ?? null,
				raw_headers: email.raw_headers ?? null,
				delivery_status: email.delivery_status ?? (isSent ? "sent" : "received"),
				delivery_operation_id: email.delivery_operation_id ?? null,
				source_draft_id: email.source_draft_id ?? null,
				inbound_key: email.inbound_key ?? null,
			})
			.run();

		if (attachments.length > 0) {
			this.db.insert(schema.attachments).values(attachments.map((attachment) => ({
				...attachment,
				object_key: attachment.object_key ?? null,
			}))).run();
		}
	}
}
