import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppEnv } from "../src/env";
import { RefreshInProgress, renewUserToken } from "../src/auth/refresh";
import { ReauthorizationRequired, type UserTokenSet } from "../src/auth/user-oauth";

/**
 * Concurrent refreshes of one grant against a fake GitHub that, like the real
 * one, accepts each refresh token exactly once. Before src/auth/refresh.ts the
 * loser of such a race got `bad_refresh_token`, which the token endpoint turns
 * into `invalid_grant`, which revokes the grant.
 */

const appEnv = env as unknown as AppEnv;

/** Refresh tokens GitHub will still accept. Each works once. */
let unspent: Set<string>;
let githubCalls: string[];
let failNextWith: "network" | undefined;

function pair(refreshToken: string): UserTokenSet {
	return {
		accessToken: "old-access",
		expiresAt: 0,
		refreshToken,
		refreshExpiresAt: 0,
	};
}

beforeEach(() => {
	unspent = new Set();
	githubCalls = [];
	failNextWith = undefined;
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const url = String(input instanceof Request ? input.url : input);
		if (!url.endsWith("/login/oauth/access_token")) {
			throw new Error(`Unexpected fetch ${url}`);
		}
		const token = new URLSearchParams(String(init?.body)).get("refresh_token") ?? "";
		githubCalls.push(token);
		// Slow enough that a concurrent refresh arrives while this one is in flight.
		await new Promise((resolve) => setTimeout(resolve, 50));
		if (failNextWith === "network") {
			failNextWith = undefined;
			throw new TypeError("Network connection lost.");
		}
		let body: Record<string, unknown>;
		if (unspent.delete(token)) {
			unspent.add(`${token}+`);
			body = {
				access_token: `access-for-${token}`,
				expires_in: 28_800,
				refresh_token: `${token}+`,
				refresh_token_expires_in: 15_811_200,
			};
		} else {
			body = { error: "bad_refresh_token", error_description: "The refresh token is spent." };
		}
		return new Response(JSON.stringify(body), {
			headers: { "Content-Type": "application/json" },
		});
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("renewUserToken", () => {
	it("gives two concurrent refreshes the same pair from one GitHub call", async () => {
		unspent.add("race-1");
		const [a, b] = await Promise.all([
			renewUserToken(appEnv, pair("race-1")),
			renewUserToken(appEnv, pair("race-1")),
		]);
		expect(githubCalls).toEqual(["race-1"]);
		expect(a.accessToken).toBe("access-for-race-1");
		expect(b).toEqual(a);
	});

	it("survives five refreshes at once", async () => {
		unspent.add("race-5");
		const results = await Promise.all(
			Array.from({ length: 5 }, () => renewUserToken(appEnv, pair("race-5"))),
		);
		expect(githubCalls).toEqual(["race-5"]);
		expect(new Set(results.map((r) => r.refreshToken))).toEqual(new Set(["race-5+"]));
	});

	it("answers a retry after a lost response without calling GitHub again", async () => {
		unspent.add("retry-1");
		const first = await renewUserToken(appEnv, pair("retry-1"));
		const retry = await renewUserToken(appEnv, pair("retry-1"));
		expect(githubCalls).toEqual(["retry-1"]);
		expect(retry).toEqual(first);
	});

	it("follows a handed-over pair that has itself been refreshed since", async () => {
		unspent.add("chain-1");
		const second = await renewUserToken(appEnv, pair("chain-1"));
		const third = await renewUserToken(appEnv, second);
		const stale = await renewUserToken(appEnv, pair("chain-1"));
		expect(githubCalls).toEqual(["chain-1", "chain-1+"]);
		expect(stale).toEqual(third);
	});

	it("still reports a spent token no concurrent refresh replaced", async () => {
		await expect(renewUserToken(appEnv, pair("spent-1"))).rejects.toBeInstanceOf(
			ReauthorizationRequired,
		);
		// The failed claim is released, so the next attempt asks GitHub again.
		await expect(renewUserToken(appEnv, pair("spent-1"))).rejects.toBeInstanceOf(
			ReauthorizationRequired,
		);
		expect(githubCalls).toEqual(["spent-1", "spent-1"]);
	});

	it("lets a waiter try GitHub itself when the claimer fails transiently", async () => {
		unspent.add("flaky-1");
		failNextWith = "network";
		const results = await Promise.allSettled([
			renewUserToken(appEnv, pair("flaky-1")),
			renewUserToken(appEnv, pair("flaky-1")),
		]);
		const fulfilled = results.filter((r) => r.status === "fulfilled");
		expect(fulfilled).toHaveLength(1);
		expect((fulfilled[0] as PromiseFulfilledResult<UserTokenSet>).value.accessToken).toBe(
			"access-for-flaky-1",
		);
		expect(githubCalls).toEqual(["flaky-1", "flaky-1"]);
	});

	it("asks the client to retry, not reauthorise, while another refresh is in flight", async () => {
		unspent.add("slow-1");
		const { sha256Hex } = await import("../src/auth/crypto");
		const id = await sha256Hex("github-issues-mcp refresh slow-1");
		await appEnv.DB.prepare(
			`INSERT INTO token_refreshes (id, sealed_tokens, claimed_at, expires_at)
			 VALUES (?1, NULL, ?2, ?3)`,
		)
			.bind(id, Date.now(), Date.now() + 60_000)
			.run();
		await expect(
			renewUserToken(appEnv, pair("slow-1"), { waitMs: 100, pollMs: 20 }),
		).rejects.toBeInstanceOf(RefreshInProgress);
		expect(githubCalls).toEqual([]);
	});

	it("stores nothing a reader of D1 could use as a credential", async () => {
		unspent.add("store-1");
		const renewed = await renewUserToken(appEnv, pair("store-1"));
		const rows = await appEnv.DB.prepare(`SELECT * FROM token_refreshes`).all();
		const dump = JSON.stringify(rows.results);
		expect(dump).not.toContain("store-1");
		expect(dump).not.toContain(renewed.accessToken);
	});
});
