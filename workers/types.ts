// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import type { EmailAgent } from "./agent";
import type { EmailMCP } from "./mcp";
import type { MailboxDO } from "./durableObject";

export interface Env extends Cloudflare.Env {
	EMAIL: SendEmail;
	OUTBOUND_QUEUE: Queue<unknown>;
	AUTO_DRAFT_QUEUE: Queue<unknown>;
	AI: Ai;
	MAILBOX: DurableObjectNamespace<MailboxDO>;
	EMAIL_AGENT: DurableObjectNamespace<EmailAgent>;
	EMAIL_MCP: DurableObjectNamespace<EmailMCP>;
	ACCESS_AUTH_ENABLED?: string;
	POLICY_AUD?: string;
	TEAM_DOMAIN?: string;
}
