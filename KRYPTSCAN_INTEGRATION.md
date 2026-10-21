# KryptScan Integration

KryptScan is mounted inside this existing onboarding Render service so we do not need a second paid Render web service.

## URL

After deployment, open:

```text
https://<your-existing-render-domain>/kryptscan/
```

If the custom domain `kryptscan.kryptnet.org` is pointed to the same Render service, the root domain redirects to KryptScan:

```text
https://kryptscan.kryptnet.org
```

The direct mounted path also works:

```text
/kryptscan/
```

## Render Service

Keep using the existing onboarding service:

```text
kryptnet-onboarding
```

Do not create another Render web service unless you later want a fully isolated KryptScan service.

## Current Mode

The integrated KryptScan defaults to:

```env
APP_ENV=staging
SCANNER_BACKEND=mock
EMAIL_DELIVERY=console
PAYMENT_DEMO_MODE=false
ALLOW_PRIVATE_NETWORK_TARGETS=false
```

This is enough for live UI testing, registration, free scan preview, report UI, and payment flow testing.

## Optional Render Environment Variables

Add these to the existing onboarding Render service when ready:

```env
KRYPTSCAN_DOMAIN=kryptscan.kryptnet.org
KRYPTSCAN_APP_ENV=staging
KRYPTSCAN_TRUSTED_HOSTS=kryptscan.kryptnet.org,*.kryptnet.org,*.onrender.com
OPENAI_API_KEY=<openai-api-key>
KRYPTNET_PAYMENT_WEBHOOK_SECRET=<payment-webhook-secret>
KRYPTNET_PAYMENT_API_URL=<payment-checkout-base-url>
KRYPTGUARD_CONSOLE_URL=https://kryptguard.kryptnet.org
```

Use `KRYPTSCAN_APP_ENV=staging` while testing. Change it to `production` only after SMTP and payment webhook secrets are configured.

In Render Custom Domains, add:

```text
kryptscan.kryptnet.org
```

In Bluehost DNS, create the CNAME record Render provides. It is usually:

```text
Host/Name: kryptscan
Type: CNAME
Points to/Value: <your-render-service>.onrender.com
```

For real OTP/report emails from KryptScan, also add:

```env
EMAIL_DELIVERY=smtp
EMAIL_FROM=support@kryptnet.org
SMTP_HOST=<smtp-host>
SMTP_PORT=587
SMTP_USERNAME=<smtp-user>
SMTP_PASSWORD=<smtp-password>
SMTP_USE_TLS=true
```

## Data

KryptScan uses these files under the onboarding service:

```text
instance/kryptscan.db
instance/kryptscan_reports/
```

These should remain runtime data and should not be committed.

## Mounted Paths

The visible KryptScan web page is served by Flask:

```text
/kryptscan/
/kryptscan/static/
```

The FastAPI backend is mounted internally at:

```text
/kryptscan-app/
```

The browser JavaScript sends API calls there automatically.

## Endpoint Agent Delivery

Authenticated owners and analysts can open **KryptNet Endpoint Protection** from the KryptScan service picker. The deployment workspace provides a direct handoff to KryptGuard for one-time enrollment and audited downloads for the current Windows Setup EXE and MSI packages.

Store release packages in private, HTTPS-capable object storage or a protected release CDN. KryptScan does not commit large installer binaries or reveal the configured storage URLs in its API; downloads pass through an authenticated audit endpoint and then redirect to the approved object.

Configure these Render variables only after the files have been built and verified:

```env
KRYPTGUARD_AGENT_VERSION=0.5.0
KRYPTGUARD_AGENT_CHANNEL=stable
KRYPTGUARD_AGENT_PUBLISHED_AT=<ISO-8601-release-time>
KRYPTGUARD_AGENT_SETUP_URL=https://<trusted-download-host>/KryptNetAgentSetup-0.5.0.exe
KRYPTGUARD_AGENT_SETUP_SHA256=<64-character-sha256>
KRYPTGUARD_AGENT_SETUP_SIZE_MB=<size-in-megabytes>
KRYPTGUARD_AGENT_MSI_URL=https://<trusted-download-host>/KryptNetAgent-0.5.0-x64.msi
KRYPTGUARD_AGENT_MSI_SHA256=<64-character-sha256>
KRYPTGUARD_AGENT_MSI_SIZE_MB=<size-in-megabytes>
KRYPTGUARD_AGENT_SIGNED=true
KRYPTGUARD_AGENT_RELEASE_READY=true
```

Production refuses to start with `KRYPTGUARD_AGENT_RELEASE_READY=true` when the release is not marked signed or when a package URL is not HTTPS. Leave both release flags false until Authenticode signing and final verification are complete.

For a controlled non-production test only, set:

```env
KRYPTSCAN_APP_ENV=staging
KRYPTGUARD_AGENT_ALLOW_UNSIGNED_TESTING=true
KRYPTGUARD_AGENT_SIGNED=false
KRYPTGUARD_AGENT_RELEASE_READY=true
```

Never enable unsigned testing in production. The installer still requires an enrollment token issued in KryptGuard; KryptScan authentication is intentionally not reused as an agent enrollment credential.

## Future Upgrade

The full scanner toolchain can still be deployed later on a separate VPS/scanner worker. This integrated Render service is mainly for the public web flow and lightweight testing.
