import { describe, expect, it } from "vitest";
import { SendEmailRequestSchema } from "../workers/lib/schemas";

const baseRequest = {
	to: "recipient@example.com",
	from: "sender@example.com",
	subject: "Hello",
	text: "Body",
};

describe("request limits", () => {
	it("rejects oversized subjects and bodies", () => {
		expect(SendEmailRequestSchema.safeParse({ ...baseRequest, subject: "x".repeat(201) }).success).toBe(false);
		expect(SendEmailRequestSchema.safeParse({ ...baseRequest, text: "x".repeat(1_048_577) }).success).toBe(false);
	});

	it("rejects too many recipients and attachments", () => {
		const recipients = Array.from({ length: 21 }, (_, index) => `user${index}@example.com`);
		const attachments = Array.from({ length: 21 }, () => ({
			content: "aGk=",
			filename: "file.txt",
			type: "text/plain",
			disposition: "attachment" as const,
		}));
		expect(SendEmailRequestSchema.safeParse({ ...baseRequest, to: recipients }).success).toBe(false);
		expect(SendEmailRequestSchema.safeParse({ ...baseRequest, attachments }).success).toBe(false);
	});

	it("requires content IDs for inline attachments", () => {
		expect(SendEmailRequestSchema.safeParse({
			...baseRequest,
			attachments: [{ content: "aGk=", filename: "pixel.png", type: "image/png", disposition: "inline" }],
		}).success).toBe(false);
	});
});
