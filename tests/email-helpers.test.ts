import { describe, expect, it } from "vitest";
import { buildReferencesChain, buildQuotedReplyBlock, textToHtml, validateSender, SenderValidationError } from "../workers/lib/email-helpers";

describe("email safety helpers", () => {
	it("builds a bounded reply reference chain", () => {
		const result = buildReferencesChain({
			id: "local-id",
			message_id: "message@example.com",
			email_references: JSON.stringify(["prior@example.com"]),
			thread_id: "thread-1",
		} as never);
		expect(result.originalMsgId).toBe("message@example.com");
		expect(result.references).toEqual(["prior@example.com", "message@example.com"]);
		expect(result.threadId).toBe("thread-1");
	});

	it("escapes plain text and quoted content", () => {
		expect(textToHtml("<script>alert(1)</script>")).not.toContain("<script>alert");
		expect(buildQuotedReplyBlock({ sender: "<attacker>", body: "<img src=x onerror=alert(1)>" })).not.toContain("onerror=alert");
	});

	it("requires the mailbox address as the sender", () => {
		expect(() => validateSender("to@example.com", "other@example.com", "sender@example.com")).toThrow(SenderValidationError);
	});
});
