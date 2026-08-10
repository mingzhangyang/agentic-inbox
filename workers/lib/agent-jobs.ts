// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import type { Env } from "../types";
import { getMailboxStub } from "./email-helpers";

export interface AutoDraftQueueMessage {
	mailboxId: string;
	emailId: string;
	sender: string;
	subject: string;
	threadId: string;
}

export async function processAutoDraftMessage(
	message: Message<AutoDraftQueueMessage>,
	env: Env,
): Promise<void> {
	const data = message.body;
	const stub = getMailboxStub(env, data.mailboxId);
	const claim = await stub.claimAutoDraftJob(data.emailId, data.mailboxId);
	if (claim !== "claimed") {
		if (claim === "pending") message.retry({ delaySeconds: 60 });
		else message.ack();
		return;
	}
	try {
		const settingsObject = await env.BUCKET.get(`mailboxes/${data.mailboxId}.json`);
		const settings = settingsObject ? await settingsObject.json<{ autoDraftMaxPerDay?: number }>() : {};
		const dailyLimit = Math.min(Math.max(settings.autoDraftMaxPerDay ?? 50, 1), 200);
		if (!(await stub.checkRateLimit("auto-draft:day", dailyLimit, 24 * 60 * 60))) {
			await stub.completeAutoDraftJob(data.emailId);
			message.ack();
			return;
		}
		const agentStub = env.EMAIL_AGENT.get(env.EMAIL_AGENT.idFromName(data.mailboxId));
		const response = await agentStub.fetch(new Request("https://agents/onNewEmail", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(data),
		}));
		if (!response.ok) throw new Error(`Agent returned ${response.status}`);
		await stub.completeAutoDraftJob(data.emailId);
		message.ack();
	} catch (error) {
		const failed = await stub.failAutoDraftJob(data.emailId, error instanceof Error ? error.message : "Unknown auto-draft error");
		if (failed.retry) message.retry({ delaySeconds: 10 });
		else message.ack();
	}
}
