import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { getOAuthApi } from "@cloudflare/workers-oauth-provider";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GrantProps } from "../src/auth/props";
import type { AppEnv } from "../src/env";
import worker from "../src/index";

/**
 * A refresh at the token endpoint, end to end: a grant is issued, its GitHub
 * token is due for renewal, and the request to GitHub fails in a way that
 * says nothing about the refresh token. The client must be told to retry
 * (503 with Retry-After), not handed an opaque 500 or an `invalid_grant`.
 */
const appEnv = env as unknown as AppEnv;
const origin = appEnv.PUBLIC_URL.replace(/\/+$/, "");
const redirectUri = "https://client.example/callback";

async function post(path: string, form: Record<string, string>): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await worker.fetch(
		new Request(`${origin}${path}`, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams(form).toString(),
		}),
		appEnv,
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
	const verifier = "v".repeat(64);
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
	const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
	return { verifier, challenge };
}

/** Issues a grant whose GitHub token has already expired, and its MCP tokens. */
async function grantDueForRenewal(refreshToken: string) {
	// Only the storage helpers are used, so the handlers here are never called.
	const helpers = getOAuthApi(
		{
			apiHandlers: { "/mcp": { fetch: () => new Response() } },
			defaultHandler: { fetch: () => new Response() },
			authorizeEndpoint: "/authorize",
			tokenEndpoint: "/token",
			resourceMetadata: { resource: `${origin}/mcp` },
		} as any,
		appEnv,
	);
	const client = await helpers.createClient({
		redirectUris: [redirectUri],
		tokenEndpointAuthMethod: "none",
	});
	const { verifier, challenge } = await pkce();
	const authorize = new URL(`${origin}/authorize`);
	authorize.search = new URLSearchParams({
		response_type: "code",
		client_id: client.clientId,
		redirect_uri: redirectUri,
		code_challenge: challenge,
		code_challenge_method: "S256",
		resource: `${origin}/mcp`,
	}).toString();
	const request = await helpers.parseAuthRequest(new Request(authorize));
	const props: GrantProps = {
		userId: 1,
		login: "octocat",
		installationId: 2,
		accountLogin: "octo-org",
		accountType: "Organization",
		user: { accessToken: "old-access", expiresAt: 0, refreshToken, refreshExpiresAt: 0 },
	};
	const { redirectTo } = await helpers.completeAuthorization({
		request,
		userId: "1",
		metadata: {},
		scope: [],
		props,
	});
	const code = new URL(redirectTo).searchParams.get("code")!;
	const issued = await post("/token", {
		grant_type: "authorization_code",
		code,
		redirect_uri: redirectUri,
		client_id: client.clientId,
		code_verifier: verifier,
	});
	expect(issued.status).toBe(200);
	const tokens = (await issued.json()) as { refresh_token: string };
	return { clientId: client.clientId, refreshToken: tokens.refresh_token };
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("refreshing at the token endpoint", () => {
	it("answers a GitHub timeout with a retryable 503", async () => {
		const grant = await grantDueForRenewal("gh-refresh-timeout");
		vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
			throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
		});

		const response = await post("/token", {
			grant_type: "refresh_token",
			refresh_token: grant.refreshToken,
			client_id: grant.clientId,
		});

		expect(response.status).toBe(503);
		expect(response.headers.get("Retry-After")).toBe("5");
		const body = (await response.json()) as { error: string };
		expect(body.error).toBe("temporarily_unavailable");
	});

	it("answers a 502 HTML page from GitHub with a retryable 503", async () => {
		const grant = await grantDueForRenewal("gh-refresh-502");
		vi.spyOn(globalThis, "fetch").mockImplementation(
			async () =>
				new Response("<html><body>502 Bad Gateway</body></html>", {
					status: 502,
					headers: { "Content-Type": "text/html" },
				}),
		);

		const response = await post("/token", {
			grant_type: "refresh_token",
			refresh_token: grant.refreshToken,
			client_id: grant.clientId,
		});

		expect(response.status).toBe(503);
		// GitHub sent no Retry-After, so the default cooldown is advertised.
		expect(response.headers.get("Retry-After")).toBe("10");
		const body = (await response.json()) as { error: string };
		expect(body.error).toBe("temporarily_unavailable");
	});

	it("passes GitHub's Retry-After on a 429 through to the client", async () => {
		const grant = await grantDueForRenewal("gh-refresh-429");
		vi.spyOn(globalThis, "fetch").mockImplementation(
			async () =>
				new Response(JSON.stringify({ message: "Too many requests" }), {
					status: 429,
					headers: { "Content-Type": "application/json", "Retry-After": "42" },
				}),
		);

		const response = await post("/token", {
			grant_type: "refresh_token",
			refresh_token: grant.refreshToken,
			client_id: grant.clientId,
		});

		expect(response.status).toBe(503);
		expect(response.headers.get("Retry-After")).toBe("42");
	});

	it("fails, rather than asking for a retry, on a non-JSON 403 from GitHub", async () => {
		const grant = await grantDueForRenewal("gh-refresh-403");
		vi.spyOn(globalThis, "fetch").mockImplementation(
			async () =>
				new Response("<html><body>Access denied</body></html>", {
					status: 403,
					headers: { "Content-Type": "text/html" },
				}),
		);

		const outcome = await post("/token", {
			grant_type: "refresh_token",
			refresh_token: grant.refreshToken,
			client_id: grant.clientId,
		}).catch((error: unknown) => error);

		if (outcome instanceof Response) {
			expect(outcome.status).not.toBe(503);
			expect(outcome.headers.get("Retry-After")).toBeNull();
		} else {
			expect(String((outcome as Error).message)).toContain("HTTP 403");
		}
	});

	it("still fails, rather than asking for a retry, when the app is misconfigured", async () => {
		const grant = await grantDueForRenewal("gh-refresh-bad-creds");
		vi.spyOn(globalThis, "fetch").mockImplementation(
			async () =>
				new Response(
					JSON.stringify({
						error: "incorrect_client_credentials",
						error_description:
							"The client_id and/or client_secret passed are incorrect.",
					}),
					{ headers: { "Content-Type": "application/json" } },
				),
		);

		// A hard failure, as before: the provider lets the error escape, and the
		// runtime answers with a 500. It must not look like a retryable 503.
		const outcome = await post("/token", {
			grant_type: "refresh_token",
			refresh_token: grant.refreshToken,
			client_id: grant.clientId,
		}).catch((error: unknown) => error);

		if (outcome instanceof Response) {
			expect(outcome.status).not.toBe(503);
			expect(outcome.headers.get("Retry-After")).toBeNull();
		} else {
			expect(String((outcome as Error).message)).toContain("incorrect");
		}
	});
});
