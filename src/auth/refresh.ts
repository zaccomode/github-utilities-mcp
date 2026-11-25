/**
 * Renews a grant's GitHub user token at most once, however many refreshes of
 * that grant arrive at the same time.
 *
 * GitHub refresh tokens are single-use, and since workers-oauth-provider 1.1
 * a refresh that throws `invalid_grant` revokes the whole grant, including any
 * tokens a concurrent refresh has just issued. The provider takes no lock
 * around `tokenExchangeCallback`, so two refreshes of one grant (two requests
 * that both got a 401, or a retry after a lost response) used to end with one
 * of them spending the refresh token and the other revoking the grant.
 *
 * Now the first refresh claims a D1 row named after the refresh token it is
 * about to spend, calls GitHub, and leaves the new pair in that row, sealed
 * with a key derived from the spent refresh token. Any other refresh holding
 * the same token finds the row, waits for the pair and returns it, so every
 * racer agrees on one pair and nobody revokes anything. The row outlives the
 * race for a few minutes, which also covers a client retrying a refresh whose
 * response it lost.
 *
 * A refresh that takes over an abandoned claim and is told the token is spent
 * cannot tell a dead grant from one whose earlier claimer spent the token and
 * saved the new pair into the grant without recording it here. It leaves the
 * row marked "outcome unknown" for a while, and until the mark lapses every
 * refresh of that token is asked to retry rather than told to reauthorise.
 */

import { sealString, sha256Hex, unsealString } from "./crypto";
import { type AppEnv, required } from "../env";
import { ReauthorizationRequired, type UserTokenSet, refreshUserToken } from "./user-oauth";

/** How long a finished refresh's pair stays available to latecomers. */
const HANDOFF_TTL_MS = 10 * 60 * 1000;

/** A claim older than this with no pair is treated as abandoned. */
const CLAIM_TIMEOUT_MS = 30 * 1000;

/**
 * The longest a claimer waits for GitHub. Well under `CLAIM_TIMEOUT_MS`, so a
 * claimer can never still be spending the refresh token when somebody else
 * takes its claim over.
 */
const GITHUB_TIMEOUT_MS = 15 * 1000;

/**
 * How long a token whose outcome is unknown (see `markOutcomeUnknown`) keeps
 * every refresh of it waiting. Long enough to outlast KV serving a grant's old
 * props in another colo (up to about a minute) plus a client's retries, short
 * enough that a token that really is dead is reported soon after.
 */
const OUTCOME_UNKNOWN_TTL_MS = 2 * 60 * 1000;

/** How many spent tokens are followed when a pair has itself been refreshed. */
const MAX_HOPS = 5;

const SEAL_INFO = "github-issues-mcp token refresh handoff v1";

export interface RenewOptions {
	/** How long to wait for a concurrent refresh to finish. */
	waitMs?: number;
	/** How often to look while waiting. */
	pollMs?: number;
	/** How long the GitHub token request may take before it is abandoned. */
	githubTimeoutMs?: number;
	/**
	 * Runs housekeeping off the critical path, e.g. `waitUntil` from
	 * `cloudflare:workers`. Without it the housekeeping is awaited.
	 */
	defer?: (promise: Promise<unknown>) => void;
}

export class RefreshInProgress extends Error {
	constructor() {
		super("Another refresh of this connection is still in progress. Try again shortly.");
		this.name = "RefreshInProgress";
	}
}

/**
 * Returns a fresh token pair for a grant whose current pair is `current`.
 * Throws `ReauthorizationRequired` only when the refresh token is spent and no
 * concurrent refresh produced a replacement, which is the one case where the
 * grant really is dead.
 */
export async function renewUserToken(
	env: AppEnv,
	current: UserTokenSet,
	options: RenewOptions = {},
): Promise<UserTokenSet> {
	const { waitMs = 8000, pollMs = 150, githubTimeoutMs = GITHUB_TIMEOUT_MS, defer } = options;
	const refreshToken = current.refreshToken;
	if (!refreshToken) {
		// Nothing to race over: GitHub issued no refresh token, so this fails
		// the same way it always did.
		return refreshUserToken(env, refreshToken);
	}

	const id = await rowId(refreshToken);
	const swept = sweep(env).catch(() => undefined);
	if (defer) {
		defer(swept);
	} else {
		await swept;
	}

	// A second pass covers a claimer that failed and released its claim: this
	// refresh then tries GitHub itself.
	for (let attempt = 0; attempt < 2; attempt++) {
		const claimed = await claim(env, id);
		if (claimed) {
			return refreshAsClaimer(env, id, refreshToken, claimed === "takeover", githubTimeoutMs);
		}

		const deadline = Date.now() + waitMs;
		let released = false;
		while (!released) {
			const row = await env.DB.prepare(
				`SELECT sealed_tokens, claimed_at, expires_at, outcome_unknown
				 FROM token_refreshes WHERE id = ?1`,
			)
				.bind(id)
				.first<{
					sealed_tokens: string | null;
					claimed_at: number;
					expires_at: number;
					outcome_unknown: number;
				}>();

			if (!row) {
				released = true;
				break;
			}
			if (row.outcome_unknown) {
				if (Date.now() < row.expires_at) {
					throw new RefreshInProgress();
				}
				// The mark has lapsed: claim() replaces it with a fresh claim.
				released = true;
				break;
			}
			if (row.sealed_tokens) {
				const pair = await open(env, refreshToken, row.sealed_tokens);
				if (pair) {
					return latest(env, pair);
				}
				// Sealed under another GITHUB_CLIENT_SECRET, or damaged: unusable.
				await env.DB.prepare(`DELETE FROM token_refreshes WHERE id = ?1`).bind(id).run();
				released = true;
				break;
			}
			if (Date.now() - row.claimed_at >= CLAIM_TIMEOUT_MS) {
				// claim() takes over an abandoned claim on the next pass.
				released = true;
				break;
			}
			if (Date.now() >= deadline) {
				throw new RefreshInProgress();
			}
			await sleep(pollMs);
		}
	}
	throw new RefreshInProgress();
}

async function refreshAsClaimer(
	env: AppEnv,
	id: string,
	refreshToken: string,
	tookOver: boolean,
	githubTimeoutMs: number,
): Promise<UserTokenSet> {
	let renewed: UserTokenSet;
	try {
		renewed = await refreshUserToken(env, refreshToken, AbortSignal.timeout(githubTimeoutMs));
	} catch (error) {
		// The claim this refresh took over may have been abandoned only in
		// appearance: its holder can have spent the token and failed to record
		// the pair, which is now in the grant. Calling the grant dead would
		// revoke it, so mark the outcome unknown, which makes this refresh and
		// every other one holding the token retry until the mark lapses. If the
		// token really is dead, a refresh after that reports it.
		if (tookOver && error instanceof ReauthorizationRequired) {
			await markOutcomeUnknown(env, id);
			throw new RefreshInProgress();
		}
		// Release the claim so anyone waiting stops waiting.
		await env.DB.prepare(`DELETE FROM token_refreshes WHERE id = ?1 AND sealed_tokens IS NULL`)
			.bind(id)
			.run()
			.catch(() => undefined);
		// GitHub being slow or unreachable is temporary: the refresh token was
		// not spent, so the client should retry rather than see a 500.
		if (isTransient(error)) {
			throw new RefreshInProgress();
		}
		throw error;
	}

	let sealed: string;
	try {
		sealed = await sealString(
			required(env, "GITHUB_CLIENT_SECRET"),
			refreshToken,
			SEAL_INFO,
			JSON.stringify(renewed),
		);
	} catch (error) {
		console.error("Could not seal a refreshed token pair:", error);
		return renewed;
	}
	for (let attempt = 1; attempt <= 2; attempt++) {
		try {
			await env.DB.prepare(
				`UPDATE token_refreshes SET sealed_tokens = ?2, expires_at = ?3 WHERE id = ?1`,
			)
				.bind(id, sealed, Date.now() + HANDOFF_TTL_MS)
				.run();
			break;
		} catch (error) {
			// The pair is good and this refresh returns it; only a concurrent
			// one loses out, and it is told to retry rather than reauthorise.
			if (attempt === 2) {
				console.error("Could not record a refreshed token pair:", error);
			}
		}
	}
	return renewed;
}

/**
 * Keeps the claim's row, flagged, until `OUTCOME_UNKNOWN_TTL_MS` from now. If
 * the write fails the row is released instead, which is no worse than before
 * the flag existed.
 */
async function markOutcomeUnknown(env: AppEnv, id: string): Promise<void> {
	try {
		await env.DB.prepare(
			`UPDATE token_refreshes SET outcome_unknown = 1, expires_at = ?2
			 WHERE id = ?1 AND sealed_tokens IS NULL`,
		)
			.bind(id, Date.now() + OUTCOME_UNKNOWN_TTL_MS)
			.run();
	} catch (error) {
		console.error("Could not mark a refresh's outcome unknown:", error);
		await env.DB.prepare(`DELETE FROM token_refreshes WHERE id = ?1 AND sealed_tokens IS NULL`)
			.bind(id)
			.run()
			.catch(() => undefined);
	}
}

/**
 * A failure that says nothing about the refresh token: the request to GitHub
 * timed out, was aborted, or never got an answer (`fetch` rejects with a
 * `TypeError` when the connection fails).
 */
function isTransient(error: unknown): boolean {
	if (error instanceof TypeError) {
		return true;
	}
	const name = (error as { name?: unknown } | null)?.name;
	return name === "TimeoutError" || name === "AbortError";
}

/**
 * Takes the row for `id`: inserts it, replaces an "outcome unknown" mark that
 * has lapsed, or takes over a claim whose holder has gone quiet without leaving
 * a pair. Truthy when this refresh should call GitHub, and `"takeover"` when
 * someone else may have spent the token first.
 */
async function claim(env: AppEnv, id: string): Promise<"fresh" | "takeover" | false> {
	const now = Date.now();
	const inserted = await env.DB.prepare(
		`INSERT INTO token_refreshes (id, sealed_tokens, claimed_at, expires_at)
		 VALUES (?1, NULL, ?2, ?3)
		 ON CONFLICT(id) DO NOTHING`,
	)
		.bind(id, now, now + HANDOFF_TTL_MS)
		.run();
	if (inserted.meta.changes === 1) {
		return "fresh";
	}
	// A lapsed mark has given any pair it was protecting time to reach the
	// grant, so a spent token now really does mean a dead grant.
	const replaced = await env.DB.prepare(
		`UPDATE token_refreshes SET outcome_unknown = 0, claimed_at = ?2, expires_at = ?3
		 WHERE id = ?1 AND outcome_unknown = 1 AND expires_at <= ?2`,
	)
		.bind(id, now, now + HANDOFF_TTL_MS)
		.run();
	if (replaced.meta.changes === 1) {
		return "fresh";
	}
	const takenOver = await env.DB.prepare(
		`UPDATE token_refreshes SET claimed_at = ?2, expires_at = ?3
		 WHERE id = ?1 AND sealed_tokens IS NULL AND outcome_unknown = 0 AND claimed_at <= ?4`,
	)
		.bind(id, now, now + HANDOFF_TTL_MS, now - CLAIM_TIMEOUT_MS)
		.run();
	return takenOver.meta.changes === 1 ? "takeover" : false;
}

/**
 * A pair handed over may itself have been refreshed since, which spent its
 * refresh token too; follow those handoffs to the newest pair.
 */
async function latest(env: AppEnv, pair: UserTokenSet): Promise<UserTokenSet> {
	let newest = pair;
	for (let hop = 0; hop < MAX_HOPS && newest.refreshToken; hop++) {
		const row = await env.DB.prepare(`SELECT sealed_tokens FROM token_refreshes WHERE id = ?1`)
			.bind(await rowId(newest.refreshToken))
			.first<{ sealed_tokens: string | null }>();
		const next = row?.sealed_tokens
			? await open(env, newest.refreshToken, row.sealed_tokens)
			: undefined;
		if (!next) {
			break;
		}
		newest = next;
	}
	return newest;
}

async function open(
	env: AppEnv,
	refreshToken: string,
	sealed: string,
): Promise<UserTokenSet | undefined> {
	try {
		const pair = JSON.parse(
			await unsealString(
				required(env, "GITHUB_CLIENT_SECRET"),
				refreshToken,
				SEAL_INFO,
				sealed,
			),
		) as UserTokenSet;
		return typeof pair?.accessToken === "string" ? pair : undefined;
	} catch {
		return undefined;
	}
}

function rowId(refreshToken: string): Promise<string> {
	// Prefixed so the id is never the bare hash of a token used elsewhere.
	return sha256Hex(`github-issues-mcp refresh ${refreshToken}`);
}

function sweep(env: AppEnv): Promise<unknown> {
	return env.DB.prepare(`DELETE FROM token_refreshes WHERE expires_at <= ?1`)
		.bind(Date.now())
		.run();
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
