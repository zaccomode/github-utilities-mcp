import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppEnv } from "../src/env";
import { RefreshInProgress, renewUserToken } from "../src/auth/refresh";
import {
	DEFAULT_RETRY_AFTER_SECONDS,
	MAX_RETRY_AFTER_SECONDS,
	ReauthorizationRequired,
	type UserTokenSet,
	parseRetryAfter,
} from "../src/auth/user-oauth";

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
let failNextWith:
	| "network"
	| "hang"
	| "html502"
	| "json503"
	| "rateLimited"
	| "rateLimitedRetryAfter"
	| "html429"
	| "html403"
	| "html404"
	| "html200"
	| "badCredentials"
	| undefined;

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
		if (failNextWith === "html502") {
			failNextWith = undefined;
			return new Response("<html><body>502 Bad Gateway</body></html>", {
				status: 502,
				headers: { "Content-Type": "text/html" },
			});
		}
		if (failNextWith === "json503") {
			failNextWith = undefined;
			return new Response(JSON.stringify({ message: "Service Unavailable" }), {
				status: 503,
				headers: { "Content-Type": "application/json" },
			});
		}
		if (failNextWith === "rateLimited") {
			failNextWith = undefined;
			return new Response(JSON.stringify({ message: "Too many requests" }), {
				status: 429,
				headers: { "Content-Type": "application/json" },
			});
		}
		if (failNextWith === "rateLimitedRetryAfter") {
			failNextWith = undefined;
			return new Response(JSON.stringify({ message: "Too many requests" }), {
				status: 429,
				headers: { "Content-Type": "application/json", "Retry-After": "42" },
			});
		}
		const htmlStatus = { html429: 429, html403: 403, html404: 404, html200: 200 } as const;
		if (failNextWith && failNextWith in htmlStatus) {
			const status = htmlStatus[failNextWith as keyof typeof htmlStatus];
			failNextWith = undefined;
			return new Response(`<html><body>${status}</body></html>`, {
				status,
				headers: { "Content-Type": "text/html" },
			});
		}
		if (failNextWith === "badCredentials") {
			failNextWith = undefined;
			return new Response(
				JSON.stringify({
					error: "incorrect_client_credentials",
					error_description: "The client_id and/or client_secret passed are incorrect.",
				}),
				{ headers: { "Content-Type": "application/json" } },
			);
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
		`SELECT sealed_tokens, outcome_unknown, cooldown, expires_at
		 FROM token_refreshes WHERE id = ?1`,
	)
		.bind(await rowIdFor(refreshToken))
		.first<{
			sealed_tokens: string | null;
			outcome_unknown: number;
			cooldown: number;
			expires_at: number;
		}>();
}

/** Lets an "outcome unknown" mark or a cooldown on `refreshToken` lapse. */
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

	for (const failure of ["html502", "json503", "rateLimited", "html429"] as const) {
		it(`cools down, rather than releasing the claim, when GitHub is unavailable (${failure})`, async () => {
			const token = `cooldown-${failure}`;
			unspent.add(token);
			failNextWith = failure;
			const error = await renewUserToken(appEnv, pair(token)).catch((e: unknown) => e);
			expect(error).toBeInstanceOf(RefreshInProgress);
			// No Retry-After from GitHub, so the default applies.
			expect((error as RefreshInProgress).retryAfterSeconds).toBe(
				DEFAULT_RETRY_AFTER_SECONDS,
			);
			const row = await rowFor(token);
			expect(row?.cooldown).toBe(1);
			expect(row?.outcome_unknown).toBe(0);
			// A retry inside the cooldown is asked to wait, without calling GitHub.
			await expect(renewUserToken(appEnv, pair(token))).rejects.toBeInstanceOf(
				RefreshInProgress,
			);
			expect(githubCalls).toEqual([token]);
			// GitHub never spent the token, so once the cooldown is over it renews.
			await lapse(token);
			const renewed = await renewUserToken(appEnv, pair(token));
			expect(renewed.accessToken).toBe(`access-for-${token}`);
			expect(githubCalls).toEqual([token, token]);
		});
	}

	it("honours GitHub's Retry-After on a 429 and passes it on", async () => {
		unspent.add("retry-after-1");
		failNextWith = "rateLimitedRetryAfter";
		const before = Date.now();
		const error = await renewUserToken(appEnv, pair("retry-after-1")).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(RefreshInProgress);
		expect((error as RefreshInProgress).retryAfterSeconds).toBe(42);
		const row = await rowFor("retry-after-1");
		expect(row?.cooldown).toBe(1);
		expect(row!.expires_at).toBeGreaterThanOrEqual(before + 42_000);
		// A retry during the cooldown is told how much of it is left, and
		// GitHub is not called again.
		const retry = await renewUserToken(appEnv, pair("retry-after-1")).catch((e: unknown) => e);
		expect(retry).toBeInstanceOf(RefreshInProgress);
		expect((retry as RefreshInProgress).retryAfterSeconds).toBeGreaterThan(30);
		expect((retry as RefreshInProgress).retryAfterSeconds).toBeLessThanOrEqual(42);
		expect(githubCalls).toEqual(["retry-after-1"]);
	});

	it("makes one GitHub call between concurrent refreshes during a 429", async () => {
		unspent.add("retry-after-2");
		failNextWith = "rateLimitedRetryAfter";
		const results = await Promise.allSettled(
			Array.from({ length: 4 }, () => renewUserToken(appEnv, pair("retry-after-2"))),
		);
		for (const result of results) {
			expect(result.status).toBe("rejected");
			const reason = (result as PromiseRejectedResult).reason;
			expect(reason).toBeInstanceOf(RefreshInProgress);
			expect(reason.retryAfterSeconds).toBeGreaterThan(30);
		}
		expect(githubCalls).toEqual(["retry-after-2"]);
	});

	it("does not take over a cooldown however old its claim is", async () => {
		unspent.add("cooldown-old-1");
		failNextWith = "rateLimitedRetryAfter";
		await expect(renewUserToken(appEnv, pair("cooldown-old-1"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		// The claim is past the takeover age, but the cooldown is still live.
		await appEnv.DB.prepare(`UPDATE token_refreshes SET claimed_at = ?2 WHERE id = ?1`)
			.bind(await rowIdFor("cooldown-old-1"), Date.now() - 60_000)
			.run();
		await expect(renewUserToken(appEnv, pair("cooldown-old-1"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		expect(githubCalls).toEqual(["cooldown-old-1"]);
	});

	for (const failure of ["html403", "html404", "html200"] as const) {
		it(`fails hard on a non-JSON answer that is not temporary (${failure})`, async () => {
			const token = `hard-${failure}`;
			unspent.add(token);
			failNextWith = failure;
			const error = await renewUserToken(appEnv, pair(token)).catch((e: unknown) => e);
			expect(error).toBeInstanceOf(Error);
			expect(error).not.toBeInstanceOf(RefreshInProgress);
			expect(error).not.toBeInstanceOf(ReauthorizationRequired);
			expect(String((error as Error).message)).toContain("text/html");
			// Released, not cooled down: nothing about it is temporary.
			expect(await rowFor(token)).toBeNull();
		});
	}

	it("still fails hard on a configuration error such as bad client credentials", async () => {
		unspent.add("creds-1");
		failNextWith = "badCredentials";
		const error = await renewUserToken(appEnv, pair("creds-1")).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(Error);
		expect(error).not.toBeInstanceOf(RefreshInProgress);
		expect(error).not.toBeInstanceOf(ReauthorizationRequired);
		expect(String((error as Error).message)).toContain("incorrect");
		expect(await rowFor("creds-1")).toBeNull();
	});

	it("keeps a takeover's row marked when its GitHub call times out", async () => {
		// The earlier claimer spent "takeover-hang-1" and saved the pair into
		// the grant without recording it here.
		await staleClaim("takeover-hang-1", 31_000);
		failNextWith = "hang";
		await expect(
			renewUserToken(appEnv, pair("takeover-hang-1"), { githubTimeoutMs: 100 }),
		).rejects.toBeInstanceOf(RefreshInProgress);
		expect((await rowFor("takeover-hang-1"))?.outcome_unknown).toBe(1);
		// The client retries with the spent token, still inside the KV
		// staleness window: it is asked to wait, not told to reauthorise.
		await expect(renewUserToken(appEnv, pair("takeover-hang-1"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		expect(githubCalls).toEqual(["takeover-hang-1"]);
		// Once the mark lapses, a token that really is dead is reported.
		await lapse("takeover-hang-1");
		await expect(renewUserToken(appEnv, pair("takeover-hang-1"))).rejects.toBeInstanceOf(
			ReauthorizationRequired,
		);
	});

	for (const failure of ["network", "html502", "json503", "badCredentials"] as const) {
		it(`keeps a takeover's row marked when its GitHub call fails (${failure})`, async () => {
			const token = `takeover-${failure}`;
			await staleClaim(token, 31_000);
			failNextWith = failure;
			await expect(renewUserToken(appEnv, pair(token))).rejects.toBeInstanceOf(
				RefreshInProgress,
			);
			expect((await rowFor(token))?.outcome_unknown).toBe(1);
			await expect(renewUserToken(appEnv, pair(token))).rejects.toBeInstanceOf(
				RefreshInProgress,
			);
			expect(githubCalls).toEqual([token]);
		});
	}

	it("keeps a takeover's mark for at least GitHub's Retry-After", async () => {
		await staleClaim("takeover-429", 31_000);
		failNextWith = "rateLimitedRetryAfter";
		const error = await renewUserToken(appEnv, pair("takeover-429")).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(RefreshInProgress);
		expect((error as RefreshInProgress).retryAfterSeconds).toBe(42);
		const row = await rowFor("takeover-429");
		expect(row?.outcome_unknown).toBe(1);
		expect(row?.cooldown).toBe(0);
	});

	it("keeps a takeover's row marked after a 5xx HTML page, then releases it to a fresh claim", async () => {
		unspent.add("takeover-html-2");
		await staleClaim("takeover-html-2", 31_000);
		failNextWith = "html502";
		await expect(renewUserToken(appEnv, pair("takeover-html-2"))).rejects.toBeInstanceOf(
			RefreshInProgress,
		);
		expect((await rowFor("takeover-html-2"))?.outcome_unknown).toBe(1);
		// The token turns out to be unspent: once the mark lapses it renews.
		await lapse("takeover-html-2");
		const renewed = await renewUserToken(appEnv, pair("takeover-html-2"));
		expect(renewed.accessToken).toBe("access-for-takeover-html-2");
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

describe("parseRetryAfter", () => {
	it("reads delay-seconds", () => {
		expect(parseRetryAfter("42")).toBe(42);
		expect(parseRetryAfter(" 7 ")).toBe(7);
	});

	it("reads an HTTP date", () => {
		const now = Date.parse("2026-01-01T00:00:00Z");
		expect(parseRetryAfter("Thu, 01 Jan 2026 00:01:00 GMT", now)).toBe(60);
	});

	it("falls back to the default when absent or unreadable", () => {
		expect(parseRetryAfter(null)).toBe(DEFAULT_RETRY_AFTER_SECONDS);
		expect(parseRetryAfter("")).toBe(DEFAULT_RETRY_AFTER_SECONDS);
		expect(parseRetryAfter("soon")).toBe(DEFAULT_RETRY_AFTER_SECONDS);
		expect(parseRetryAfter("-5")).toBe(DEFAULT_RETRY_AFTER_SECONDS);
	});

	it("keeps the wait between one second and the cap", () => {
		expect(parseRetryAfter("0")).toBe(1);
		const now = Date.parse("2026-01-01T00:00:00Z");
		expect(parseRetryAfter("Wed, 31 Dec 2025 23:00:00 GMT", now)).toBe(1);
		expect(parseRetryAfter("86400")).toBe(MAX_RETRY_AFTER_SECONDS);
	});
});
