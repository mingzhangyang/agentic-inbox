<div align="center">
  <h1>Agentic Inbox</h1>
  <p><em>A self-hosted email client with an AI agent, running entirely on Cloudflare Workers</em></p>
</div>

Agentic Inbox lets you send, receive, and manage emails through a modern web interface -- all powered by your own Cloudflare account. Incoming emails arrive via [Cloudflare Email Routing](https://developers.cloudflare.com/email-routing/), each mailbox is isolated in its own [Durable Object](https://developers.cloudflare.com/durable-objects/) with a SQLite database, and attachments are stored in [R2](https://developers.cloudflare.com/r2/).

An **AI-powered Email Agent** can read your inbox, search conversations, and draft replies -- built with the [Cloudflare Agents SDK](https://developers.cloudflare.com/agents/) and [Workers AI](https://developers.cloudflare.com/workers-ai/).

![Agentic Inbox screenshot](./demo_app.png)


Read the blog post to learn more about Cloudflare Email Service and how to use it with the Agents SDK, MCP, and from the Wrangler CLI: [Email for Agents](https://blog.cloudflare.com/email-for-agents/).

## How to setup

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cloudflare/agentic-inbox)

Click the button above to deploy to your Cloudflare account. The deploy flow will automatically provision R2, Durable Objects, and Workers AI. You'll be prompted for:

- **DOMAINS** -- your domain with Email Routing enabled (e.g. `example.com`)

### After deploying

1. **Set up Email Routing** -- In the Cloudflare dashboard, go to your domain > Email Routing and create a catch-all rule that forwards to this Worker
2. **Enable Email Service** -- The worker needs the `send_email` binding to send outbound emails. See [Email Service docs](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/)
3. **Create a mailbox** -- Visit your deployed app and create a mailbox for any address on your domain (e.g. `hello@example.com`)
4. **Configure Cloudflare Access** -- Auth is enabled by default in production. Enable [one-click Cloudflare Access](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/) on your Worker under Settings > Domains & Routes. The modal will show your `POLICY_AUD` and `TEAM_DOMAIN` values.
5. **Auth mode** -- Leave `ACCESS_AUTH_ENABLED` unset or set it to `"true"` with `POLICY_AUD` and `TEAM_DOMAIN` to enforce Cloudflare Access JWT validation. Set `ACCESS_AUTH_ENABLED=false` only for local development or intentionally public deployments.

## Features

- **Full email client** — Send and receive emails via Cloudflare Email Routing with a rich text composer, reply/forward threading, folder organization, search, and attachments
- **Per-mailbox isolation** — Each mailbox runs in its own Durable Object with SQLite storage and R2 for attachments
- **Built-in AI agent** — Side panel with 9 email tools for reading, searching, drafting, and sending
- **Auto-draft on new email** — Agent automatically reads inbound emails and generates draft replies, always requiring explicit confirmation before sending. Set per-mailbox `autoDraftEnabled` to `false` to disable this behavior.
- **Durable delivery** — Outbound mail is recorded in an Outbox before it is queued. Queue retries use a stable operation ID and Message-ID; delivery status is available from the API.
- **Configurable and persistent** — Custom system prompts per mailbox, persistent chat history, streaming markdown responses, and tool call visibility

## Stack

- **Frontend:** React 19, React Router v7, Tailwind CSS, Zustand, TipTap, `@cloudflare/kumo`
- **Backend:** Hono, Cloudflare Workers, Durable Objects (SQLite), R2, Email Routing
- **AI Agent:** Cloudflare Agents SDK (`AIChatAgent`), AI SDK v6, Workers AI (`@cf/moonshotai/kimi-k2.5`), `react-markdown` + `remark-gfm`
- **Auth:** Cloudflare Access JWT validation enabled by default in production

## Agent Cost Controls

Auto-draft runs on inbound mail when `autoDraftEnabled` is not `false`. Each auto-draft attempt can call Workers AI for prompt-injection scanning, draft generation, and draft verification. Disable auto-draft per mailbox for high-volume addresses that should only be reviewed manually.

The default `autoDraftMaxPerDay` is 50 and the configured maximum is 200. Auto-drafts are processed through a queue and deduplicated by mailbox and inbound email ID.

## Getting Started

```bash
npm install
npm run dev
```

### Configuration

1. Set your domain in `wrangler.jsonc`
2. Create the R2 buckets used by your selected environment, for example: `wrangler r2 bucket create agentic-inbox` and `wrangler r2 bucket create agentic-inbox-staging`
3. Create the queues and dead-letter queues: `wrangler queues create agentic-inbox-outbound`, `wrangler queues create agentic-inbox-outbound-dlq`, `wrangler queues create agentic-inbox-auto-draft`, and `wrangler queues create agentic-inbox-auto-draft-dlq`
4. Local development is dry-run by default (`DRY_RUN_EMAILS=true`). Set `DRY_RUN_EMAILS=false` only in the production environment after Email Service and routing have been verified.

### Deploy

```bash
npm run deploy
# or, for an explicit environment configuration
wrangler deploy --env staging
wrangler deploy --env production
```

## Prerequisites

- Cloudflare account with a domain
- [Email Routing](https://developers.cloudflare.com/email-routing/) enabled for receiving
- [Email Service](https://developers.cloudflare.com/email-service/) enabled for sending
- [Workers AI](https://developers.cloudflare.com/workers-ai/) enabled (for the agent)
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) configured for deployed/shared environments (recommended when exposing this app publicly)

When Access is enabled, any user who passes the shared Cloudflare Access policy can access all mailboxes in this app by design. This includes the MCP server at `/mcp` -- external AI tools (Claude Code, Cursor, etc.) connected via MCP can operate on any mailbox by passing a `mailboxId` parameter. There is no per-mailbox authorization; the Cloudflare Access policy is the single trust boundary.

This release intentionally keeps that single-operator/shared-Access model. Team-level mailbox ACLs, per-user ownership, and audit attribution are follow-up work; do not expose the deployment to a broader Access group until those controls are implemented.

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser    │────>│  Hono Worker     │────>│  MailboxDO      │
│  React SPA   │     │  (API + SSR)     │     │  (SQLite + R2)  │
│  Agent Panel │     │                  │     └─────────────────┘
└──────┬───────┘     │  /agents/* ──────┼────>┌─────────────────┐
       │             │                  │     │  EmailAgent DO  │
       │ WebSocket   │                  │     │  (AIChatAgent)  │
       └─────────────┤                  │     │  9 email tools  │
                     │                  │────>│  Workers AI     │
└──────────────────┘     └─────────────────┘
```

Outbound sends and auto-draft jobs are persisted in the mailbox Durable Object and dispatched through Cloudflare Queues. R2 object keys are stored with attachment metadata so cleanup does not depend on reconstructing filenames.

## Verification

```bash
npm run verify
```

This runs Wrangler type validation, TypeScript, the production build (including React Router generation), and the unit test suite. The delivery model is at-least-once: provider-side duplicate suppression or operational reconciliation is still required if a worker crashes after the provider accepts a message but before the Outbox is marked `sent`.

## License

Apache 2.0 -- see [LICENSE](LICENSE).
