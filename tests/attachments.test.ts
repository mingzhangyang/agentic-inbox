import { describe, expect, it } from "vitest";
import { storeAttachments } from "../workers/lib/attachments";

function createBucket() {
	const objects = new Map<string, Uint8Array>();
	return {
		objects,
		put: async (key: string, value: Uint8Array) => {
			objects.set(key, new Uint8Array(value));
			return null;
		},
		delete: async (keys: string | string[]) => {
			for (const key of Array.isArray(keys) ? keys : [keys]) objects.delete(key);
		},
	};
}

describe("attachment storage", () => {
	it("stores a stable object key in the returned metadata", async () => {
		const bucket = createBucket();
		const [attachment] = await storeAttachments(bucket as never, "email-1", [{
			content: "aGk=",
			filename: "hello.txt",
			type: "text/plain",
			disposition: "attachment",
		}]);
		expect(attachment.object_key).toBe(`attachments/email-1/${attachment.id}/hello.txt`);
		expect(bucket.objects.has(attachment.object_key)).toBe(true);
	});

	it("rejects malformed base64 before writing", async () => {
		const bucket = createBucket();
		await expect(storeAttachments(bucket as never, "email-1", [{
			content: "not base64!",
			filename: "hello.txt",
			type: "text/plain",
			disposition: "attachment",
		}])).rejects.toThrow("valid base64");
		expect(bucket.objects.size).toBe(0);
	});
});
