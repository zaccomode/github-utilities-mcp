-- Serialises refreshes of a GitHub user token; see src/auth/refresh.ts.
--
-- GitHub refresh tokens are single-use, and since workers-oauth-provider 1.1 a
-- failed refresh revokes the whole grant. Two refreshes racing on one grant
-- must therefore make one GitHub call between them: the first claims the row,
-- and the second waits for the pair the first one gets.
--
-- In D1 rather than KV because the claim has to be atomic, which KV's eventual
-- consistency cannot promise. The refresh token is never stored, only its
-- SHA-256. `sealed_tokens` holds the new pair encrypted with a key derived
-- from the refresh token it replaced, so it is unreadable without that token,
-- which only the grant itself holds.

CREATE TABLE token_refreshes (
	id            TEXT    PRIMARY KEY,   -- hex SHA-256 of the spent refresh token
	sealed_tokens TEXT,                  -- NULL while the refresh is in flight
	claimed_at    INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL
);
CREATE INDEX idx_token_refreshes_expires ON token_refreshes(expires_at);
