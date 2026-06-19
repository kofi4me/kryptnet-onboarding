# KryptScan Integration

KryptScan is mounted inside this existing onboarding Render service so we do not need a second paid Render web service.

## URL

After deployment, open:

```text
https://<your-existing-render-domain>/kryptscan/
```

If a custom domain is configured, KryptScan can also be reached from that domain under:

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
OPENAI_API_KEY=<openai-api-key>
KRYPTNET_PAYMENT_WEBHOOK_SECRET=<payment-webhook-secret>
KRYPTNET_PAYMENT_API_URL=<payment-checkout-base-url>
```

For real OTP/report emails from KryptScan, also add:

```env
EMAIL_DELIVERY=smtp
EMAIL_FROM=security@kryptnet.org
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

## Future Upgrade

The full scanner toolchain can still be deployed later on a separate VPS/scanner worker. This integrated Render service is mainly for the public web flow and lightweight testing.
