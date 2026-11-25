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
let failNextWith: "network" | "hang" | undefined;

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
		if (failNextWith === "hang") {
			failNextWith = undefined;
			// Never answers; only the caller's abort signal ends it.
			await new Promise((_, reject) => {
				init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
			});
		}
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

async function rowIdFor(refreshToken: string): Promise<string> {
	const { sha256Hex } = await import("../src/auth/crypto");
	return sha256Hex(`github-issues-mcp refresh ${refreshToken}`);
}

/** Leaves a claim on `refreshToken` that has had no pair for `ageMs`. */
async function staleClaim(refreshToken: string, ageMs: number): Promise<void> {
	const claimedAt = Date.now() - ageMs;
	await appEnv.DB.prepare(
		`INSERT INTO token_refreshes (id, sealed_tokens, claimed_at, expires_at)
		 VALUES (?1, NULL, ?2, ?3)`,
	)
		.bind(await rowIdFor(refreshToken), claimedAt, Date.now() + 60_000)
		.run();
}

async function rowFor(refreshToken: string) {
	return appEnv.DB.prepare(
		`SELECT sealed_tokens, outcome_unknown FROM token_refreshes WHERE id = ?1`,
	)
		.bind(await rowIdFor(refreshToken))
		.first<{ sealed_tokens: string | null; outcome_unknown: number }>();
}

/** Lets an "outcome unknown" mark on `refreshToken` lapse. */
async function lapse(refreshToken: string): Promise<void> {
	await appEnv.DB.prepare(`UPDATE token_refreshes SET expires_at = ?2 WHERE id = ?1`)
		.bind(await rowIdFor(refreshToken), Date.now() - 1)
		.run();
}

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

	it("does not report a dead grant after taking over a claim whose holder spent the token", async () => {
		// The holder spent "takeover-1" (it is not in `unspent`) and wrote the
		// new pair into the grant, but never recorded it here.
		await staleClaim("takeover-1", 31_000);
		await expect(renewUserToken(appEnv, pair("takeover-1"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		expect(githubCalls).toEqual(["takeover-1"]);
		// The row stays, marked, so nobody claims it afresh while the grant may
		// still be catching up.
		expect((await rowFor("takeover-1"))?.outcome_unknown).toBe(1);
		// Once the mark lapses, a genuinely dead token is still reported.
		await lapse("takeover-1");
		await expect(renewUserToken(appEnv, pair("takeover-1"))).rejects.toBeInstanceOf(
			ReauthorizationRequired,
		);
		expect(githubCalls).toEqual(["takeover-1", "takeover-1"]);
	});

	it("does not report a dead grant to a refresh waiting alongside a takeover", async () => {
		await staleClaim("takeover-9", 31_000);
		const results = await Promise.allSettled([
			renewUserToken(appEnv, pair("takeover-9")),
			renewUserToken(appEnv, pair("takeover-9")),
		]);
		for (const result of results) {
			expect(result.status).toBe("rejected");
			expect((result as PromiseRejectedResult).reason).toBeInstanceOf(RefreshInProgress);
		}
		expect(githubCalls).toEqual(["takeover-9"]);
	});

	it("keeps asking a client that retries after the 503 to wait while the mark is live", async () => {
		await staleClaim("takeover-10", 31_000);
		await expect(renewUserToken(appEnv, pair("takeover-10"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		// The retry carries the same pair, as it would if it read stale props.
		await expect(renewUserToken(appEnv, pair("takeover-10"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		expect(githubCalls).toEqual(["takeover-10"]);
	});

	it("claims a lapsed mark afresh even before it is swept", async () => {
		await staleClaim("takeover-11", 31_000);
		await expect(renewUserToken(appEnv, pair("takeover-11"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		// Lapsed, but not yet swept: the next refresh claims it afresh, so a
		// dead token is reported rather than retried forever.
		await appEnv.DB.prepare(`UPDATE token_refreshes SET expires_at = ?2 WHERE id = ?1`)
			.bind(await rowIdFor("takeover-11"), Date.now() + 50)
			.run();
		await new Promise((resolve) => setTimeout(resolve, 60));
		await expect(
			renewUserToken(appEnv, pair("takeover-11"), { defer: () => undefined }),
		).rejects.toBeInstanceOf(ReauthorizationRequired);
	});

	it("still renews normally after taking over an abandoned claim", async () => {
		unspent.add("takeover-2");
		await staleClaim("takeover-2", 31_000);
		const renewed = await renewUserToken(appEnv, pair("takeover-2"));
		expect(renewed.accessToken).toBe("access-for-takeover-2");
	});

	it("abandons a GitHub call that outlasts its timeout and releases the claim", async () => {
		unspent.add("hang-1");
		failNextWith = "hang";
		await expect(
			renewUserToken(appEnv, pair("hang-1"), { githubTimeoutMs: 100 }),
		).rejects.toBeInstanceOf(RefreshInProgress);
		expect(await rowFor("hang-1")).toBeNull();
		// The token was never spent, so the retry renews it.
		const renewed = await renewUserToken(appEnv, pair("hang-1"));
		expect(renewed.accessToken).toBe("access-for-hang-1");
	});

	it("asks the client to retry when GitHub cannot be reached", async () => {
		unspent.add("offline-1");
		failNextWith = "network";
		await expect(renewUserToken(appEnv, pair("offline-1"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		expect(await rowFor("offline-1")).toBeNull();
	});

	it("retries recording the pair once when the first write fails", async () => {
		unspent.add("seal-1");
		let failures = 0;
		const flakyDb = new Proxy(appEnv.DB, {
			get(target, key, receiver) {
				if (key === "prepare") {
					return (sql: string) => {
						const statement = target.prepare(sql);
						if (sql.includes("SET sealed_tokens") && failures === 0) {
							failures++;
							return {
								bind: () => ({
									run: () => Promise.reject(new Error("D1_ERROR: transient")),
								}),
							};
						}
						return statement;
					};
				}
				return Reflect.get(target, key, receiver);
			},
		});
		const renewed = await renewUserToken({ ...appEnv, DB: flakyDb } as AppEnv, pair("seal-1"));
		expect(failures).toBe(1);
		expect((await rowFor("seal-1"))?.sealed_tokens).toBeTruthy();
		// A latecomer gets the recorded pair without calling GitHub.
		const late = await renewUserToken(appEnv, pair("seal-1"));
		expect(late).toEqual(renewed);
		expect(githubCalls).toEqual(["seal-1"]);
	});

	it("can run its housekeeping off the critical path", async () => {
		unspent.add("defer-1");
		const deferred: Promise<unknown>[] = [];
		await renewUserToken(appEnv, pair("defer-1"), { defer: (p) => deferred.push(p) });
		expect(deferred).toHaveLength(1);
		await Promise.all(deferred);
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
