# Credential Rotation Runbook (Part 8 §12-§13, §93)

## Secret inventory

- `SECRET_STORE_MASTER_KEY` — envelope key for the encrypted file secret store (base64 32 bytes).
- `INTERNAL_SERVICE_TOKEN_SECRET` — HMAC key for zero-trust internal service tokens (§5).
- `GOOGLE_API_KEY` — model provider key (read directly from the environment, never copied into config, DB or logs).
- API credentials / PATs — `api_credentials` rows with hashes, owner, scopes, expiry, last use.
- Credential grants — engagement/identity/target/purpose-scoped, TTL-bounded (§14-§15).

## Rotation procedure

1. Generate the new secret in the deployment secret manager.
2. For the secret store master key: re-encrypt `data/secrets/secrets.json` with the new key (offline script: read with old key, write with new key).
3. For the internal service token secret: redeploy services; tokens are short-lived (TTL 5-15 minutes), so old tokens expire naturally.
4. For provider keys: update the environment, restart the API; model calls record provider + model id (never the key).
5. Revoke existing grants if compromise is suspected: the emergency stop revokes all issued grants at once (§89).
6. Verify: `/api/ready` green; a fresh API-key create/auth/revoke cycle succeeds (integration test covers it).

## Kill switches (§93)

- Single grant: `POST /api/engagements/:id/grants/:gid/revoke`
- Engagement: pause + `revokeAllForEngagement` (engagement kill switch)
- Platform: `POST /api/security/emergency-stop/engage` (revokes every issued grant)
