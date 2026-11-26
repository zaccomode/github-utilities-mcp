-- Holds back refreshes of a token while GitHub is unavailable; see
-- src/auth/refresh.ts.
--
-- When GitHub answers a refresh with a 408, 429 or 5xx, the refresh token was
-- not spent, but asking again straight away only adds to the load, and on a
-- 429 can stretch GitHub's secondary rate limit. So the claim's row is kept
-- with this flag set until `expires_at`, which follows GitHub's Retry-After.
-- Until then every refresh of the token is asked to retry without calling
-- GitHub; afterwards the next refresh claims the row afresh.

ALTER TABLE token_refreshes ADD COLUMN cooldown INTEGER NOT NULL DEFAULT 0;
