-- Marks a refresh token whose fate is unknown; see src/auth/refresh.ts.
--
-- A refresh that takes over an abandoned claim and is then told the token is
-- spent cannot tell a dead grant from one whose previous claimer spent the
-- token and saved the new pair into the grant without recording it here.
-- Rather than deleting the row, which let the next refresh claim afresh and
-- revoke the grant, it is kept with this flag set until `expires_at`. While it
-- is set every refresh of that token is asked to retry; once it lapses a token
-- that really is dead is reported as such.

ALTER TABLE token_refreshes ADD COLUMN outcome_unknown INTEGER NOT NULL DEFAULT 0;
