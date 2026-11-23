/**
 * Upload links: short-lived, single-use URLs on this Worker that accept one
 * release asset and pass it on to GitHub.
 *
 * They exist because a file must not travel inside a tool call. Base64 adds a
 * third to the size, and the model would have to read and type out every byte
 * exactly. Instead `create_release_asset_upload` hands back a link, the agent
 * sends the file from its shell with curl, and src/uploads/handler.ts streams
 * it on to GitHub as whichever identity the link was made for.
 *
 * A link is a bearer secret, so only its hash is stored. The secret travels in
 * the upload's `Authorization: Bearer` header, never in the URL: the URL holds
 * only that hash, the link's id, because request URLs end up in Workers Logs.
 * For act_as "user" the person's token has to survive until the upload
 * arrives, and it is sealed with a key derived from both the secret and a
 * Worker secret. Neither the row nor the URL can be turned into a GitHub
 * credential or used to upload, which keeps the promise that D1 holds none.
 * The sealed token is cleared as soon as the link is claimed, and from every
 * row once its link has expired.
 *
 * Each link also names the OAuth grant that made it. The upload handler
 * refuses a link whose grant has been revoked since, so disconnecting the
 * connector stops its links working too.
 */

import { type GrantRef } from "../auth/props";
import { randomToken, sealString, sha256Hex, unsealString } from "../auth/crypto";
import { type AppEnv, required } from "../env";
import type { Actor } from "../github/client";

/** Long enough to run a build and send it; the clock stops when the upload starts. */
export const LINK_TTL_SECONDS = 15 * 60;

/** Expired rows are kept this long after expiry, then swept. */
const SWEEP_AFTER_SECONDS = 24 * 60 * 60;

export const UPLOAD_PATH_PREFIX = "/uploads/";

export interface NewUploadLink {
	grant: GrantRef;
	installationId: number;
	accountLogin: string;
	actor: Actor;
	userLogin: string;
	/** Required when `actor` is "user": the token the upload will run as. */
	userToken?: string;
	owner: string;
	repo: string;
	releaseId: number;
	name: string;
	label?: string;
	contentType: string;
}

export interface ClaimedUploadLink {
	/** Missing only on links made before grants were recorded. */
	grant?: GrantRef;
	installationId: number;
	accountLogin: string;
	actor: Actor;
	userLogin: string;
	/** Unsealed; present only when `actor` is "user". */
	userToken?: string;
	owner: string;
	repo: string;
	releaseId: number;
	name: string;
	label?: string;
	contentType: string;
}

interface Row {
	grant_user_id: string | null;
	grant_id: string | null;
	installation_id: number;
	account_login: string;
	actor: Actor;
	user_login: string;
	sealed_token: string | null;
	owner: string;
	repo: string;
	release_id: number;
	name: string;
	label: string | null;
	content_type: string;
	expires_at: number;
	used_at: number | null;
}

/**
 * Stores a new link and returns its secret, sent as the upload's bearer token,
 * and its id, the last path segment of the URL.
 */
export async function createUploadLink(
	env: AppEnv,
	link: NewUploadLink,
): Promise<{ id: string; secret: string; expiresAt: number }> {
	if (link.actor === "user" && !link.userToken) {
		throw new Error("An upload link acting as the user needs the user's token.");
	}

	const secret = randomToken();
	const now = Math.floor(Date.now() / 1000);
	const expiresAt = now + LINK_TTL_SECONDS;
	const sealed = link.actor === "user" ? await seal(env, secret, link.userToken!) : null;
	const id = await uploadLinkId(secret);

	await env.DB.prepare(
		`INSERT INTO upload_links (id, installation_id, account_login, actor, user_login,
			sealed_token, owner, repo, release_id, name, label, content_type, created_at,
			expires_at, grant_user_id, grant_id)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)`,
	)
		.bind(
			id,
			link.installationId,
			link.accountLogin,
			link.actor,
			link.userLogin,
			sealed,
			link.owner,
			link.repo,
			link.releaseId,
			link.name,
			link.label ?? null,
			link.contentType,
			now,
			expiresAt,
			link.grant.userId,
			link.grant.grantId,
		)
		.run();

	return { id, secret, expiresAt };
}

export type ClaimResult =
	| { ok: true; link: ClaimedUploadLink }
	| { ok: false; reason: "unknown" | "used" | "expired" | "unreadable" };

/**
 * Marks a link used and returns it, or says why it cannot be used. The update
 * is the claim: of two requests racing on one link, exactly one sees a row.
 * The sealed token is then cleared from the row, used or not: from here on it
 * lives only in this request.
 */
export async function claimUploadLink(env: AppEnv, secret: string): Promise<ClaimResult> {
	const id = await uploadLinkId(secret);
	const now = Math.floor(Date.now() / 1000);

	const row = await env.DB.prepare(
		`UPDATE upload_links SET used_at = ?2
		 WHERE id = ?1 AND used_at IS NULL AND expires_at > ?2
		 RETURNING *`,
	)
		.bind(id, now)
		.first<Row>();

	if (!row) {
		// Only to choose the error message; the claim above already failed.
		const existing = await env.DB.prepare(
			`SELECT used_at, expires_at FROM upload_links WHERE id = ?1`,
		)
			.bind(id)
			.first<Pick<Row, "used_at" | "expires_at">>();
		if (!existing) {
			return { ok: false, reason: "unknown" };
		}
		return { ok: false, reason: existing.used_at !== null ? "used" : "expired" };
	}

	let userToken: string | undefined;
	if (row.sealed_token) {
		try {
			userToken = await unseal(env, secret, row.sealed_token);
		} catch {
			// Sealed under a key this Worker no longer derives: the link predates
			// a change of GITHUB_CLIENT_SECRET, or of the sealing scheme.
		} finally {
			// A separate statement, because RETURNING gives the row as updated,
			// and the claim needed the token before it was cleared.
			await env.DB.prepare(`UPDATE upload_links SET sealed_token = NULL WHERE id = ?1`)
				.bind(id)
				.run();
		}
		if (userToken === undefined) {
			return { ok: false, reason: "unreadable" };
		}
	}

	return {
		ok: true,
		link: {
			grant:
				row.grant_user_id && row.grant_id
					? { userId: row.grant_user_id, grantId: row.grant_id }
					: undefined,
			installationId: row.installation_id,
			accountLogin: row.account_login,
			actor: row.actor,
			userLogin: row.user_login,
			userToken,
			owner: row.owner,
			repo: row.repo,
			releaseId: row.release_id,
			name: row.name,
			label: row.label ?? undefined,
			contentType: row.content_type,
		},
	};
}

/**
 * Clears the sealed token from every link that can no longer be used, and
 * deletes links that expired a day or more ago; the rest of the row is kept
 * that long only to tell a late upload why its link failed. Run through
 * `waitUntil`.
 */
export async function sweepUploadLinks(env: AppEnv): Promise<void> {
	try {
		const now = Math.floor(Date.now() / 1000);
		await env.DB.batch([
			env.DB.prepare(
				`UPDATE upload_links SET sealed_token = NULL
				 WHERE sealed_token IS NOT NULL AND (expires_at <= ?1 OR used_at IS NOT NULL)`,
			).bind(now),
			env.DB.prepare(`DELETE FROM upload_links WHERE expires_at < ?1`).bind(
				now - SWEEP_AFTER_SECONDS,
			),
		]);
	} catch (error) {
		console.error("uploads: failed to sweep expired links", error);
	}
}

// ----------------------------------------------------------------- crypto

/** A link's id: the hex SHA-256 of its secret. Not secret; it names the row. */
export function uploadLinkId(secret: string): Promise<string> {
	return sha256Hex(secret);
}

/**
 * The link's secret is the input key material and GITHUB_CLIENT_SECRET the HKDF
 * salt, so the link alone cannot open the row. GITHUB_CLIENT_SECRET is used
 * because every deployment already has it; rotating it leaves links made
 * before the rotation unable to act as the user, and they expire within
 * fifteen minutes. The info string keeps the key distinct from the SHA-256
 * used as the row id, which is stored in the clear.
 */
const SEAL_INFO = "github-issues-mcp upload link token seal v2";

function seal(env: AppEnv, secret: string, plaintext: string): Promise<string> {
	return sealString(required(env, "GITHUB_CLIENT_SECRET"), secret, SEAL_INFO, plaintext);
}

function unseal(env: AppEnv, secret: string, sealed: string): Promise<string> {
	return unsealString(required(env, "GITHUB_CLIENT_SECRET"), secret, SEAL_INFO, sealed);
}
