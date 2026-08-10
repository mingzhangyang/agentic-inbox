import { describe, expect, it } from "vitest";
import { hashPayload } from "../workers/lib/outbox";

describe("outbox idempotency fingerprint", () => {
	it("is deterministic for the same request payload", async () => {
		const first = await hashPayload({ to: "a@example.com", subject: "Hello", body: "Hi" });
		const second = await hashPayload({ to: "a@example.com", subject: "Hello", body: "Hi" });
		expect(first).toBe(second);
		expect(first).toMatch(/^[a-f0-9]{64}$/);
	});

	it("changes when delivery content changes", async () => {
		const first = await hashPayload({ to: "a@example.com", body: "Hi" });
		const second = await hashPayload({ to: "a@example.com", body: "Changed" });
		expect(first).not.toBe(second);
	});
});
