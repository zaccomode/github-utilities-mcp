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
});
