// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { routeAgentRequest } from "agents";
import { Hono } from "hono";
import { jwtVerify, createRemoteJWKSet } from "jose";
import { createRequestHandler } from "react-router";
import { app as apiApp, receiveEmail } from "./index";
import { EmailMCP } from "./mcp";
import type { Env } from "./types";

export { MailboxDO } from "./durableObject";
export { EmailAgent } from "./agent";
export { EmailMCP } from "./mcp";

declare module "react-router" {
	export interface AppLoadContext {
		cloudflare: {
			env: Env;
			ctx: ExecutionContext;
		};
	}
}

const requestHandler = createRequestHandler(
	() => import("virtual:react-router/server-build"),
	import.meta.env.MODE,
);

const ACCESS_AUTH_ENABLED_DEFAULT = false;

function parseBooleanEnv(value: string | undefined, defaultValue: boolean) {
	if (value === undefined) return defaultValue;
	const normalized = value.trim().toLowerCase();
	if (["1", "true", "yes", "on"].includes(normalized)) return true;
	if (["0", "false", "no", "off"].includes(normalized)) return false;
	return defaultValue;
}

function normalizeTeamDomain(raw: string | undefined): string {
	const domain = (raw ?? "").trim();
	if (!domain) return "";
	return domain.startsWith("http://") || domain.startsWith("https://")
		? domain
		: `https://${domain}`;
}

function getCfAuthorizationCookie(cookieHeader: string | undefined): string | undefined {
	if (!cookieHeader) return undefined;
	const pairs = cookieHeader.split(";");
	for (const pair of pairs) {
		const [rawKey, ...rawValueParts] = pair.split("=");
		if (!rawKey || rawValueParts.length === 0) continue;
		if (rawKey.trim() !== "CF_Authorization") continue;
		const rawValue = rawValueParts.join("=").trim();
		if (!rawValue) return undefined;
		try {
			return decodeURIComponent(rawValue);
		} catch {
			return rawValue;
		}
	}
	return undefined;
}

// Main app that wraps the API and adds React Router fallback
const app = new Hono<{ Bindings: Env }>();

// Cloudflare Access JWT validation middleware (production only)
app.use("*", async (c, next) => {
	// Skip validation in development
	if (import.meta.env.DEV) {
		return next();
	}

	const accessAuthEnabled = parseBooleanEnv(
		c.env.ACCESS_AUTH_ENABLED,
		ACCESS_AUTH_ENABLED_DEFAULT,
	);
	if (!accessAuthEnabled) {
		return next();
	}

	const { POLICY_AUD } = c.env;
	const TEAM_DOMAIN = normalizeTeamDomain(c.env.TEAM_DOMAIN);

	// Fail closed in production if Access is not configured.
	if (!POLICY_AUD || !TEAM_DOMAIN) {
		return c.text(
			"Cloudflare Access auth is enabled but not configured. Set POLICY_AUD and TEAM_DOMAIN, or set ACCESS_AUTH_ENABLED=false to disable this check.",
			500,
		);
	}

	const token =
		c.req.header("cf-access-jwt-assertion")
		?? getCfAuthorizationCookie(c.req.header("cookie"));
	if (!token) {
		return c.text(
			"Missing required CF Access JWT. Enable Cloudflare Access on this route or set ACCESS_AUTH_ENABLED=false.",
			403,
		);
	}

	try {
		const JWKS = createRemoteJWKSet(
			new URL(`${TEAM_DOMAIN.replace(/\/+$/, "")}/cdn-cgi/access/certs`),
		);
		await jwtVerify(token, JWKS, {
			issuer: TEAM_DOMAIN.replace(/\/+$/, ""),
			audience: POLICY_AUD,
		});
	} catch {
		return c.text("Invalid or expired Access token", 403);
	}

	// Authorization model note: once a teammate passes the shared Cloudflare
	// Access policy, they can access all mailboxes in this app by design.
	return next();
});

// MCP server endpoint — used by AI coding tools (ProtoAgent, Claude Code, Cursor, etc.)
// Must be before API routes and React Router catch-all
const mcpHandler = EmailMCP.serve("/mcp", { binding: "EMAIL_MCP" });
app.all("/mcp", async (c) => {
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});
app.all("/mcp/*", async (c) => {
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});

// Mount the API routes
app.route("/", apiApp);

// Agent WebSocket routing - must be before React Router catch-all
app.all("/agents/*", async (c) => {
	const response = await routeAgentRequest(c.req.raw, c.env);
	if (response) return response;
	return c.text("Agent not found", 404);
});

// React Router catch-all: serves the SPA for all non-API routes
app.all("*", (c) => {
	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx as ExecutionContext },
	});
});

// Export the Hono app as the default export with an email handler
export default {
	fetch: app.fetch,
	async email(
		event: { raw: ReadableStream; rawSize: number },
		env: Env,
		ctx: ExecutionContext,
	) {
		try {
			await receiveEmail(event, env, ctx);
		} catch (e) {
			console.error("Failed to process incoming email:", (e as Error).message, (e as Error).stack);
			// Re-throw so Cloudflare's email routing can retry delivery or bounce the message.
			// Swallowing the error would silently drop the email.
			throw e;
		}
	},
};
