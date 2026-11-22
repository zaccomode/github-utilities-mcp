import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { type AppEnv, canonicalPublicUrl } from "../src/env";
import worker from "../src/index";

/**
 * In a file of its own because src/index.ts builds the OAuth provider once per
 * isolate: these requests must be the first it sees, with a broken PUBLIC_URL.
 */
describe("with an invalid PUBLIC_URL", () => {
	const broken = { ...(env as unknown as AppEnv), PUBLIC_URL: "http://example.com" };

	async function get(path: string, init?: RequestInit) {
		const ctx = createExecutionContext();
		const response = await worker.fetch(
			new Request(`https://example.com${path}`, init),
			broken,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		return response;
	}

	it("still answers the health check", async () => {
		const response = await get("/healthz");
		expect(response.status).toBe(200);
		expect(await response.text()).toBe("ok\n");
	});

	it("still routes webhooks without building the OAuth provider", async () => {
		const response = await get("/webhooks/github", { method: "POST", body: "{}" });
		expect(response.status).not.toBe(500);
	});

	it("names the setting on every other route", async () => {
		const response = await get("/authorize");
		expect(response.status).toBe(500);
		expect(((await response.json()) as { error: string }).error).toMatch(
			/PUBLIC_URL .* must use https/,
		);
	});
});

describe("canonicalPublicUrl", () => {
	it("trims any number of trailing slashes", () => {
		expect(canonicalPublicUrl("https://mcp.example.com")).toBe("https://mcp.example.com");
		expect(canonicalPublicUrl("https://mcp.example.com/")).toBe("https://mcp.example.com");
		expect(canonicalPublicUrl("https://mcp.example.com///")).toBe("https://mcp.example.com");
		expect(canonicalPublicUrl("https://mcp.example.com/base//")).toBe(
			"https://mcp.example.com/base",
		);
	});

	it("stays linear on a long run of slashes", () => {
		const start = Date.now();
		expect(canonicalPublicUrl(`https://mcp.example.com/a${"/".repeat(50_000)}`)).toBe(
			"https://mcp.example.com/a",
		);
		expect(Date.now() - start).toBeLessThan(1000);
	});

	it("lowercases the scheme and host and drops a default port", () => {
		expect(canonicalPublicUrl("HTTPS://MCP.Example.COM:443/")).toBe("https://mcp.example.com");
	});

	it("allows http only on loopback", () => {
		expect(canonicalPublicUrl("http://localhost:8787")).toBe("http://localhost:8787");
		expect(() => canonicalPublicUrl("http://mcp.example.com")).toThrow(/must use https/);
	});

	it("refuses values that cannot be a resource identifier", () => {
		expect(() => canonicalPublicUrl("mcp.example.com")).toThrow(/not an absolute URL/);
		expect(() => canonicalPublicUrl("https://mcp.example.com/?a=1")).toThrow(/query/);
		expect(() => canonicalPublicUrl("ftp://mcp.example.com")).toThrow(/https/);
	});
});
