/**
 * Small crypto helpers shared by the App JWT signer and the webhook verifier.
 *
 * Deliberately absent: anything that encrypts a GitHub token for storage. The
 * user's access and refresh tokens live in the OAuth grant's `props`, which
 * @cloudflare/workers-oauth-provider encrypts using the issued MCP token as key
 * material — so they cannot be recovered from KV without a live token. Mirroring
 * them anywhere else would trade that property away for nothing.
 *
 * The two exceptions keep the same property, using `sealString` below:
 *
 * - An upload link made to act as the user carries that user's token sealed
 *   under a key derived from the link, which is never stored, and a Worker
 *   secret. See src/uploads/links.ts.
 * - A refreshed GitHub token pair is handed to a concurrent refresh of the same
 *   grant sealed under a key derived from the refresh token it replaced, which
 *   only that grant's props hold. See src/auth/refresh.ts.
 */

export function base64ToBytes(value: string): Uint8Array {
	// Accepts base64url too, since secrets get pasted from all sorts of places.
	const normalised = value.trim().replace(/-/g, "+").replace(/_/g, "/");
	const binary = atob(normalised);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A URL-safe random string, for OAuth `state` values. */
export function randomToken(bytes = 32): string {
	return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/**
 * Constant-time string comparison, for webhook signatures. `===` on strings
 * leaks the position of the first differing byte through timing.
 */
export function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let difference = 0;
	for (let i = 0; i < a.length; i++) {
		difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return difference === 0;
}

const encoder = new TextEncoder();

/**
 * An AES-GCM key from HKDF-SHA-256. `material` is the secret that must be held
 * to open the result; `salt` is a Worker secret, so the material alone is not
 * enough either; `info` keeps keys for different purposes apart.
 */
async function sealingKey(salt: string, material: string, info: string): Promise<CryptoKey> {
	const key = await crypto.subtle.importKey("raw", encoder.encode(material), "HKDF", false, [
		"deriveKey",
	]);
	return crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: encoder.encode(salt), info: encoder.encode(info) },
		key,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

/** Encrypts `plaintext` as base64url(iv || ciphertext). */
export async function sealString(
	salt: string,
	material: string,
	info: string,
	plaintext: string,
): Promise<string> {
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		await sealingKey(salt, material, info),
		encoder.encode(plaintext),
	);
	const out = new Uint8Array(iv.length + ciphertext.byteLength);
	out.set(iv);
	out.set(new Uint8Array(ciphertext), iv.length);
	return bytesToBase64Url(out);
}

/** Reverses `sealString`; throws if the key is wrong or the data was altered. */
export async function unsealString(
	salt: string,
	material: string,
	info: string,
	sealed: string,
): Promise<string> {
	const bytes = base64ToBytes(sealed);
	const plaintext = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: bytes.slice(0, 12) },
		await sealingKey(salt, material, info),
		bytes.slice(12),
	);
	return new TextDecoder().decode(plaintext);
}

/** Hex SHA-256, for naming a row after a secret without storing the secret. */
export async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
