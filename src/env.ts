import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

/**
 * The runtime environment, as the rest of the code wants to see it.
 *
 * Three things need fixing up over the generated `Env`. Secrets never appear in
 * wrangler.jsonc, so `wrangler types` cannot know about them; plain vars are
 * generated as the *literal* value in the config file, so `GITHUB_APP_ID` would
 * otherwise be typed as the empty string; and `wrangler types` reads secret names
 * from .dev.vars and types each as a required string, but the webhook secret is
 * optional — without it, src/auth/webhook.ts answers 501 instead of verifying.
 */
export interface AppEnv extends Omit<
	Env,
	| "GITHUB_APP_ID"
	| "GITHUB_APP_SLUG"
	| "GITHUB_CLIENT_ID"
	| "PUBLIC_URL"
	| "DEFAULT_MONTHLY_QUOTA"
	| "GITHUB_WEBHOOK_SECRET"
> {
	GITHUB_APP_ID: string;
	GITHUB_APP_SLUG: string;
	GITHUB_CLIENT_ID: string;
	PUBLIC_URL: string;
	DEFAULT_MONTHLY_QUOTA: string;

	/** Secrets. `wrangler secret put <name>`; see README. */
	GITHUB_APP_PRIVATE_KEY: string;
	GITHUB_CLIENT_SECRET: string;
	GITHUB_WEBHOOK_SECRET?: string;

	/** Injected by @cloudflare/workers-oauth-provider at runtime. */
	OAUTH_PROVIDER: OAuthHelpers;
}

/**
 * Fails loudly at the point of use rather than producing a confusing GitHub
 * error three calls later. Misconfiguration is by far the likeliest failure on
 * a fresh deploy, so it is worth naming the exact missing binding.
 */
export function required(env: AppEnv, name: keyof AppEnv): string {
	const value = env[name];
	if (typeof value !== "string" || value.length === 0) {
		throw new Error(
			`${String(name)} is not configured. Set it in wrangler.jsonc (vars) or with ` +
				`\`wrangler secret put ${String(name)}\`, then redeploy.`,
		);
	}
	return value;
}

/**
 * The externally reachable base URL, canonicalised and without a trailing
 * slash. `new URL()` lowercases the scheme and host and drops a default port,
 * which the OAuth provider insists on for its resource identifier; anything
 * that still cannot serve as one is refused here with a message naming the
 * setting, rather than as an opaque error from inside the provider.
 */
export function publicUrl(env: AppEnv): string {
	return canonicalPublicUrl(required(env, "PUBLIC_URL"));
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function canonicalPublicUrl(value: string): string {
	const problem = (why: string) =>
		new Error(
			`PUBLIC_URL ${JSON.stringify(value)} ${why} Fix it in wrangler.jsonc, then redeploy.`,
		);

	let url: URL;
	try {
		url = new URL(value.trim());
	} catch {
		throw problem("is not an absolute URL.");
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		throw problem("must use https.");
	}
	if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
		throw problem("must use https; plain http is only allowed for localhost.");
	}
	if (url.username || url.password || url.search || url.hash) {
		throw problem("must not contain credentials, a query string or a fragment.");
	}

	// Trimmed with a loop, not /\/+$/: that regex backtracks quadratically on a
	// long run of slashes (CodeQL js/polynomial-redos).
	let path = url.pathname;
	while (path.endsWith("/")) {
		path = path.slice(0, -1);
	}
	return `${url.origin}${path}`;
}

/** Where GitHub sends the browser back after the OAuth handshake. */
export function callbackUrl(env: AppEnv): string {
	return `${publicUrl(env)}/callback`;
}

/** The page that installs the App on an account the user chooses. */
export function installUrl(env: AppEnv, state: string): string {
	const slug = encodeURIComponent(required(env, "GITHUB_APP_SLUG"));
	return `https://github.com/apps/${slug}/installations/new?state=${encodeURIComponent(state)}`;
}

export function defaultMonthlyQuota(env: AppEnv): number {
	const parsed = Number(env.DEFAULT_MONTHLY_QUOTA);
	return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 5000;
}
