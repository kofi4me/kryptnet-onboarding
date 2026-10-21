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

## Future Upgrade

The full scanner toolchain can still be deployed later on a separate VPS/scanner worker. This integrated Render service is mainly for the public web flow and lightweight testing.
