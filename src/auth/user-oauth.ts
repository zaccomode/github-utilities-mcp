/**
 * The user-to-server half of the GitHub App: the OAuth web flow that produces a
 * token acting as the signed-in human.
 *
 * A GitHub App's user tokens carry no OAuth scopes — what they can reach is the
 * app's declared permissions intersected with the user's own access — so no
 * `scope` parameter is sent anywhere in this file.
 */

import { type AppEnv, callbackUrl, required } from "../env";
import { ghRaw } from "../github/client";

const GITHUB_OAUTH = "https://github.com";

export interface UserTokenSet {
	accessToken: string;
	/** Epoch seconds. GitHub issues these with an 8-hour life. */
	expiresAt: number;
	refreshToken: string;
	/** Epoch seconds. Roughly six months out. */
	refreshExpiresAt: number;
}

export interface GitHubUser {
	id: number;
	login: string;
	name?: string;
	type: string;
}

export interface UserInstallation {
	id: number;
	accountId: number;
	accountLogin: string;
	accountType: "User" | "Organization";
	repositorySelection: "all" | "selected";
}

/** Where we send the browser to begin the handshake. */
export function buildAuthorizeUrl(env: AppEnv, state: string): string {
	const url = new URL("/login/oauth/authorize", GITHUB_OAUTH);
	url.searchParams.set("client_id", required(env, "GITHUB_CLIENT_ID"));
	// Built from configuration, never from the inbound request's Host header —
	// that header is attacker-influenceable, and GitHub requires an exact match
	// against the registered callback anyway.
	url.searchParams.set("redirect_uri", callbackUrl(env));
	url.searchParams.set("state", state);
	return url.toString();
}

export async function exchangeCode(env: AppEnv, code: string): Promise<UserTokenSet> {
	return tokenRequest(env, {
		client_id: required(env, "GITHUB_CLIENT_ID"),
		client_secret: required(env, "GITHUB_CLIENT_SECRET"),
		code,
		redirect_uri: callbackUrl(env),
	});
}

/**
 * Exchanges a refresh token for a new pair. Using a refresh token invalidates
 * both halves of the previous pair, so the result must be persisted — see the
 * `tokenExchangeCallback` in src/index.ts, which is the only place this is
 * called from.
 */
export async function refreshUserToken(
	env: AppEnv,
	refreshToken: string,
	signal?: AbortSignal,
): Promise<UserTokenSet> {
	return tokenRequest(
		env,
		{
			client_id: required(env, "GITHUB_CLIENT_ID"),
			client_secret: required(env, "GITHUB_CLIENT_SECRET"),
			grant_type: "refresh_token",
			refresh_token: refreshToken,
		},
		signal,
	);
}

/** Thrown when GitHub says the refresh token is spent or revoked. */
export class ReauthorizationRequired extends Error {
	constructor(detail: string) {
		super(
			"Your GitHub sign-in has expired and could not be renewed. Disconnect and " +
				`reconnect the connector to continue. (${detail})`,
		);
		this.name = "ReauthorizationRequired";
	}
}

/** The wait used when GitHub is unavailable but sends no `Retry-After`. */
export const DEFAULT_RETRY_AFTER_SECONDS = 10;

/**
 * The longest wait honoured from GitHub's `Retry-After`. A longer one is cut
 * to this, so a mistaken header cannot lock a grant out for hours.
 */
export const MAX_RETRY_AFTER_SECONDS = 300;

/**
 * Thrown when GitHub gave no usable OAuth answer and said, by its status, that
 * the problem is on its side or temporary: a 408, 429 or 5xx, whether the body
 * is an HTML error page or JSON without an OAuth `error`. Like a timeout, this
 * says nothing about the refresh token, which GitHub did not get as far as
 * spending.
 */
export class GitHubUnavailable extends Error {
	/** How long GitHub asked us to wait, or a default when it did not say. */
	readonly retryAfterSeconds: number;

	constructor(detail: string, retryAfterSeconds = DEFAULT_RETRY_AFTER_SECONDS) {
		super(`GitHub's token endpoint is temporarily unavailable. (${detail})`);
		this.name = "GitHubUnavailable";
		this.retryAfterSeconds = retryAfterSeconds;
	}
}

/**
 * Reads a `Retry-After` header, either delay-seconds or an HTTP date, into a
 * whole number of seconds between 1 and `MAX_RETRY_AFTER_SECONDS`. Absent or
 * unreadable headers give `DEFAULT_RETRY_AFTER_SECONDS`.
 */
export function parseRetryAfter(header: string | null, now = Date.now()): number {
	const value = header?.trim();
	if (!value) {
		return DEFAULT_RETRY_AFTER_SECONDS;
	}
	let seconds: number;
	if (/^\d+$/.test(value)) {
		seconds = Number(value);
	} else if (/^[+-]?[\d.]+$/.test(value)) {
		// Negative or fractional: not valid delay-seconds, and Date.parse
		// would happily read "-5" as a year.
		return DEFAULT_RETRY_AFTER_SECONDS;
	} else {
		const at = Date.parse(value);
		if (Number.isNaN(at)) {
			return DEFAULT_RETRY_AFTER_SECONDS;
		}
		seconds = Math.ceil((at - now) / 1000);
	}
	return Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, seconds));
}

/** Statuses that mean "not now" rather than "no". */
function isTemporaryStatus(status: number): boolean {
	return status === 408 || status === 429 || status >= 500;
}

async function tokenRequest(
	env: AppEnv,
	params: Record<string, string>,
	signal?: AbortSignal,
): Promise<UserTokenSet> {
	const response = await fetch(`${GITHUB_OAUTH}/login/oauth/access_token`, {
		method: "POST",
		signal,
		headers: {
			Accept: "application/json",
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent": "github-issues-mcp",
		},
		body: new URLSearchParams(params).toString(),
	});

	// Read as text first: during an incident GitHub answers with an HTML error
	// page, and `response.json()` would throw a bare SyntaxError for it.
	const text = await response.text();
	let payload: any;
	try {
		payload = JSON.parse(text);
	} catch {
		const detail = `HTTP ${response.status}, ${response.headers.get("Content-Type") ?? "no content type"}`;
		// Only a status that says "try later" makes an unreadable body a
		// temporary problem. Anything else, such as a 403 page from abuse
		// detection or a firewall, a 404, or HTML on a 200, will not fix
		// itself, so it fails visibly instead of being retried forever.
		if (isTemporaryStatus(response.status)) {
			throw new GitHubUnavailable(
				detail,
				parseRetryAfter(response.headers.get("Retry-After")),
			);
		}
		throw new Error(`GitHub's token endpoint gave an unreadable answer (${detail}).`);
	}

	// GitHub reports OAuth failures as HTTP 200 with an `error` key, so the
	// status alone tells you nothing. An OAuth error is a real answer whatever
	// the status: a spent token or a misconfigured app is not worth retrying.
	if (payload?.error) {
		const detail = payload.error_description ?? payload.error;
		if (payload.error === "bad_refresh_token" || payload.error === "bad_verification_code") {
			throw new ReauthorizationRequired(String(detail));
		}
		throw new Error(`GitHub refused the token request: ${detail}`);
	}

	if (isTemporaryStatus(response.status)) {
		throw new GitHubUnavailable(
			`HTTP ${response.status}`,
			parseRetryAfter(response.headers.get("Retry-After")),
		);
	}

	if (!payload?.access_token) {
		throw new Error(`GitHub returned no access token (HTTP ${response.status}).`);
	}

	const now = Math.floor(Date.now() / 1000);
	return {
		accessToken: payload.access_token,
		expiresAt: now + Number(payload.expires_in ?? 28_800),
		refreshToken: payload.refresh_token ?? "",
		refreshExpiresAt: now + Number(payload.refresh_token_expires_in ?? 15_811_200),
	};
}

export async function fetchUser(token: string): Promise<GitHubUser> {
	const user = await ghRaw<any>(token, "/user");
	return {
		id: user.id,
		login: user.login,
		name: user.name ?? undefined,
		type: user.type,
	};
}

/**
 * The installations of *this app* that the given user can reach.
 *
 * This is the authority on which installation a grant may be bound to. GitHub
 * puts an `installation_id` on the post-install redirect, but anyone can forge
 * that query parameter, so it is only ever cross-checked against this list —
 * never trusted on its own.
 */
export async function listUserInstallations(token: string): Promise<UserInstallation[]> {
	const found: UserInstallation[] = [];

	for (let page = 1; page <= 10; page++) {
		const result = await ghRaw<any>(token, "/user/installations", {
			query: { per_page: 100, page },
		});
		const batch: any[] = result.installations ?? [];

		for (const installation of batch) {
			found.push({
				id: installation.id,
				accountId: installation.account?.id,
				accountLogin: installation.account?.login ?? "unknown",
				accountType:
					installation.account?.type === "Organization" ? "Organization" : "User",
				repositorySelection: installation.repository_selection ?? "selected",
			});
		}

		if (batch.length < 100) {
			break;
		}
	}

	return found;
}
