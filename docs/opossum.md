# Opossum Protocol

**Move money without unnecessarily exposing your financial life. Keep your own record. Decide what you reveal.**

Opossum is a privacy-preserving transaction relay with a personal financial ledger. It keeps three things apart that conventional payment platforms fuse together:

| Layer | What it does | Where it lives |
|---|---|---|
| Moving money | a minimal payment instruction handed to an established processor | Opossum relay + Stripe Connect (or the sandbox) |
| Proving and accounting for money | signed, selectively disclosable receipts; the user's full ledger, budgets and reports | receipts: signed by the relay, kept by the user; ledger: **on the user's device**, encrypted |
| Revealing identity | legal name, address, date of birth | an encrypted identity vault that recipients never see and that is opened only for a recorded legal case |

```
conventional:  transaction → platform collects → platform stores → platform exposes as needed
opossum:       transaction → minimal relay record → user-controlled private ledger → selective disclosure
```

The relay is a legitimate technical intermediary. It does not create identities, fake people or accounts, and it does not misrepresent who controls an account. It distinguishes *"the recipient doesn't need to know who I am"* (a privacy feature) from *"nobody may know who I am"* (which financial law does not allow); only the first is offered.

- App: `/opossum`
- Receipt verifier: `/opossum/verify`
- Receipt signing key: `/opossum/.well-known/jwks.json`
- Operations and compliance: the **opossum** room of `/admin`

## 1. How a payment works

```
USER DEVICE ──signed request──▶ OPOSSUM RELAY ──payment instruction──▶ STRIPE CONNECT ──▶ RECIPIENT
     │                               │                                                       │
     │ keeps: category, note,        │ keeps: amount, fees, status, time,                    │ sees: amount, what they
     │ budget, receipt, context      │ recipient, payer pseudonym,                           │ receive, transaction ID,
     │                               │ encrypted link to the account                         │ pseudonym, and only the
     │                               │                                                       │ fields the payer chose
```

1. **Quote.** The app asks for a quote. Every figure is computed by the fee engine before confirmation: amount sent, Opossum fee, payment/network fee, total cost and what the recipient receives.
2. **Sign.** The user confirms. The browser signs the exact request bytes with the device's ECDSA P-256 key. That key was created in the browser as non-extractable, and the request carries a nonce, a timestamp and an idempotency key.
3. **Checks.** The relay runs, in order:
   - the device signature (the device must be active);
   - replay protection (nonce, 5-minute window) and idempotency (a retry returns the same payment);
   - that the total still matches what the user saw;
   - that an authenticator is on;
   - compliance limits for the jurisdiction;
   - a duplicate guard;
   - a per-hour payment limit.
4. **Pseudonym.** The relay picks the payer's pseudonym according to the privacy mode (see §3).
5. **Processor.**
   - **Stripe:** a Checkout Session is a destination charge. The recipient is a Stripe connected account, and Opossum's fee is the application fee. The payer pays on Stripe's page; card details go to Stripe, never to Opossum or the recipient.
   - **Sandbox:** settles at once with test money, and every sandbox receipt says `"test": true`.
6. **Receipt.** On settlement (instantly for the sandbox, or on Stripe's signed webhook) the relay signs a receipt. The app files the payment in the private ledger with the category and note that never left the device.

## 2. The personal ledger

Everything below runs in the browser on the decrypted ledger. None of it is sent to the relay:

- **Entries:** income, expenses, transfers, purchases, recurring payments, subscriptions, bills, donations, reimbursements, business expenses, taxes and savings.
- **Organisation:** accounts and balances, notes, receipts, transaction IDs, dates, amounts, merchants, and user-defined categories.
- **Categorisation:** automatic, from keywords, the recipient's category and learned rules. When the user changes a category, a rule is learned and applied to the same merchant.
- **Budgeting engine:**
  - monthly and weekly spending, and spending by category;
  - recurring and subscription detection (median interval and amounts within 20%);
  - disposable income, savings rate, budget use, upcoming obligations and 30/60/90-day cash-flow projection;
  - business and tax-relevant totals;
  - category budgets, savings goals, emergency reserve, business expense limit and recurring savings allocation.
- **Reports:** monthly statement, income, expenses, business, tax, reimbursement and custom date range. Exports are CSV (guarded against formula injection), spreadsheet (a real `.xlsx` written in the browser), PDF (print / save as PDF) and JSON.
- **CSV import:** bank statements can be imported, and they stay on the device.

### Keys and encryption

```
password ──PBKDF2-SHA256 (600,000 iterations, per-account salt)──▶ 512 bits
                                                   ├─ first 256 bits: auth key → sent; server stores scrypt(auth key)
                                                   └─ last 256 bits:  key-encryption key → never leaves the device
recovery code (24 base32 characters, 120 bits) ──same derivation──▶ recovery auth key + recovery key-encryption key

ledger key (random AES-256-GCM) ── wrapped by both key-encryption keys
ledger ── AES-256-GCM(ledger key) ──▶ IndexedDB on the device, and optionally the server backup (ciphertext only)
```

- The password never reaches the server, and the server can decrypt neither the ledger nor the backup.
- **Losing the phone does not lose the records.** Sign in on a new device with the password, or with the recovery code if the authenticator was on the lost phone. The encrypted backup is fetched and unwrapped in the browser.
- **Recovery** also sets a new password, switches MFA off, revokes every old device and signs every session out.
- **Resync from the relay.** Signed receipts are also re-downloaded from the relay's minimal records. So even without a backup, a new device regains the list of Opossum payments; only the private context is lost.
- **Encrypted-backup merges.** Two devices editing the same ledger merge per entry (newest change wins), with tombstones for deletions and optimistic concurrency on the backup version.

## 3. Privacy modes

| Mode | Recipient sees |
|---|---|
| private | a one-time pseudonym (`opx_…`), the amount and what they receive. Nothing links this payment to any other. |
| pseudonymous (default) | a pairwise pseudonym (`opp_…`): HMAC of the account and recipient. The same shop recognises a returning customer; two shops cannot match their customers. |
| disclosure | the pairwise pseudonym plus exactly the identity fields the payer ticks (legal name, email). |
| public | legal name and email from the identity vault. |

In every mode the payer can add a short message that the recipient will see. The payer's category, note, budget and other payments are never sent.

**Anti-tracking.** There is no public, permanent identifier. The relay's transaction IDs are random. The owner link in the relay is a keyed hash, so a database dump alone does not group payments by person.

## 4. Receipts and selective disclosure

Receipts follow the IETF OAuth working group's *Selective Disclosure for JWTs* (SD-JWT) design, using established primitives only:

- **Signing:** each claim becomes a salted SHA-256 digest inside a JWT signed with **Ed25519**. Three decoy digests hide how many claims there are.
- **Claims:**
  - the transaction ID, amount, currency, fees, total cost, what the recipient received, and the fee bearer;
  - date, time and status;
  - recipient name, handle and category, the payer pseudonym, the privacy mode, the type and the processor;
  - the invoice ID and reference, if any;
  - a memo commitment, if any;
  - the payer's legal name and identity status, if an identity is on file.
- **Always visible:** issuer, issue time, version and `test`. A sandbox receipt can never pass as a real payment.
- **Proving a private note:** the browser can commit to a private note as `sha256(salt ":" note)`. The relay signs only that hash; later the user can reveal the note and salt to prove what they wrote at payment time (for example "business: client dinner").

The **receipts** room builds a *disclosure package*:

- **Selection:** one or more receipts, with only the ticked fields revealed and each audience's defaults set in the privacy control centre.
- **Optional extras:** proven notes, and the user's own category and note, clearly marked as *stated by the payer, not signed*.

The package can be checked three ways:

- `/opossum/verify`: runs in the reader's browser with WebCrypto Ed25519, falling back to the relay only if the browser lacks it;
- `scripts/opossum_verify.py package.json --jwks <url or file>`: fully offline;
- `POST /opossum/api/verify`.

This covers proofs such as "I paid this invoice", "I paid $500", "on this date", "it was a business expense (my note, proven)" and "I have records for these transactions". It does so without revealing other transactions, balances, merchants, recipients or notes.

**Not covered by the MVP:**

- key binding (proving the presenter holds the receipt);
- zero-knowledge range proofs (e.g. "I spent less than X") without revealing amounts.

Both are possible later additions and are not claimed now.

## 5. Data map

The app's **privacy** room shows the full map (served at `/opossum/api/data-map`). In short:

| Data | Stored | Visible to |
|---|---|---|
| ledger, categories, notes, budgets, goals | device (encrypted); optional backup as ciphertext | the user only |
| password | never stored; scrypt of a derived key | nobody |
| email, legal name, address, date of birth, phone | encrypted identity vault (AES-256-GCM, bound to its row) | user; recipient only if chosen; compliance staff for identity checks (recorded); authorities with a legal order |
| payment amount, fees, status, time, recipient | relay record | user, recipient, relay, processor, authorities with a legal order |
| link between payment and account | keyed tag plus encrypted envelope | relay (automated); compliance staff only through a recorded case |
| card or bank details | Stripe, never Opossum | processor, bank |
| stablecoin paid through Stripe Checkout | Stripe; the relay keeps the network and transaction hash on the receipt | processor, and anyone reading that blockchain |
| on-chain payment (Bitcoin, USDC): amount, sending wallet, receiving address, transaction id | the blockchain itself (public, permanent); the relay keeps the deposit address, amount and transaction id | **everyone**: a public blockchain cannot be made private. Who the payer is stays off the chain and away from the recipient |
| merchant's Bitcoin xpub and USDC address | encrypted on the relay | relay (to derive addresses and watch the chain); never shown to payers |
| IP address, browser | rate limiting in memory; browser name with the session | relay, hosting providers |

Nothing is described as "not collected" when a processor, bank, host or the law necessarily receives it.

**Retention.**

- Relay records are deleted when the jurisdiction's retention period ends (default 5 years, configurable per country).
- A closed account's identity is deleted once no retained record needs it; the backup and sessions are deleted at closing.
- Nonces and idempotency keys expire within a day.

## 6. Fees

| Setting | Default |
|---|---|
| Opossum fee | **3% of the transaction value** |
| Processor fee as quoted | 2.9% + 0.30 (Stripe US cards; `OPOSSUM_PROCESSOR_FEE_PERCENT` / `_FLAT`) |
| Who bears fees | recipient (taken from the amount) or payer (added on top, grossed up so the recipient gets the full amount) |

Example, $100 with fees borne by the recipient: $3.00 Opossum fee, $3.20 processor fee, **$93.80 received**, total cost $100.00.

**Rules** (admin, *opossum* room or `/admin/api/opossum/fee-rules`) can set:

- a percentage, a flat part, a minimum and a maximum;
- per recipient (merchant pricing), per transaction type, or both;
- a start and end time for promotional pricing.

The most specific rule wins; a time-limited rule beats a permanent one, then the higher priority. The quoted processor fee is what the user pays; any difference from Stripe's actual fee is absorbed by the platform. Before confirming, the user always sees the amount sent, the Opossum fee (with the rule's name), the payment/network fee, the total cost and what the recipient receives. If anything changed since review, the relay refuses with `quote_changed` and shows the new figures.

## 7. Security model

| Control | Implementation |
|---|---|
| Strong authentication | Client-side PBKDF2 (600k iterations); scrypt verifier on the server; lockout per IP and per account |
| MFA | TOTP (RFC 6238). Required for payments by default. Required to add a device once enabled. Each code works once. |
| Device authorisation | Per-device ECDSA P-256 key, non-extractable in WebCrypto (hardware-backed where the platform provides it); devices listed and revocable |
| Transaction signing | Every payment request is signed over its exact bytes |
| Replay protection and idempotency | Nonce plus 5-minute timestamp window; idempotency keys return the same payment on retry and refuse a different payment under the same key |
| Sessions | `__Host-opossum_session` cookie (Secure, HttpOnly, SameSite=Strict); 30 min idle / 12 h max; bound to the browser; only a hash stored |
| Cross-site protection | Same-origin checks plus a custom header on every state-changing request |
| Encryption at rest | Identity vault, device-to-payment envelope, recipient-visible disclosures and stored receipts: AES-256-GCM, each bound to its table, row and field |
| Keys | One `OPOSSUM_MASTER_KEY`; HKDF-SHA256 derives separate signing, vault, pseudonym and index keys |
| Tamper-evident audit trail | Hash-chained entries; appends lock the chain head; `verify` detects edits, deletions and truncation |
| Fraud controls | Duplicate guard, payments per hour, per-payment and 24-hour limits, screening |
| Page hardening | `script-src 'self'`, Trusted Types `'none'`, COOP/COEP/CORP, restrictive Permissions-Policy, no third-party code, text-only DOM, idle auto-lock that wipes the page |
| Rate limiting | Sign-ins, payments and the platform's existing IP limits |

The browser console cannot be switched off by any website. The design makes it useless to an attacker:

- no password, session or ledger key is ever readable from page script;
- the ledger key exists only in memory while unlocked;
- the page shows a warning to anyone told to paste something.

## 8. Compliance architecture

Opossum keeps routine payments private from *recipients*. It does not evade KYC, AML, sanctions, tax obligations, court orders, fraud investigations, payment-network rules or financial regulation.

- **Per jurisdiction** (admin, `op_jurisdictions`): unverified per-payment and 24-hour limits, the verified per-payment limit, retention days, and a blocked flag. Defaults come from configuration. Limits apply to nominal amounts in the payment currency; the MVP does no FX conversion.
- **Sanctions:**
  - Blocked countries (`OPOSSUM_BLOCKED_COUNTRIES`, default CU, IR, KP, SY) apply to payers and recipients.
  - The official **OFAC SDN list** is downloaded automatically, with its alternate names, and refreshed daily (see §9a). Other lists (UN, EU, UK) can be loaded through the admin API.
  - After each refresh every identity and recipient is re-screened.
  - A match puts the account or recipient into review, and payments pause until a person decides.
- **Identity:**
  - Real-money payments need at least a self-attested identity in the vault.
  - Verified status raises limits.
  - A user can verify with **Stripe Identity** (document and live capture, optionally a selfie). Stripe sees the document; Opossum gets only verified or not, with an opaque reference (see §9a).
  - Compliance staff can still open an identity for review from the admin; each opening is recorded in the audit chain.
  - Recipients are verified by Stripe Connect onboarding.
- **Legal disclosure:** a case records the legal basis, the reference, the authority, the scope, and whether the user may be told (now, later, or prohibited by the order).
  - Disclosure needs an open case and discloses **only the listed fields** about the payer of **one** transaction. Fields available are: legal name, email, address, date of birth, phone, identity status, account ID, device ID, and the account's payments in a date range.
  - Each disclosure is written to the audit chain and to the user's *disclosures about you* list, unless the order forbids it.
  - Routine admin views never show who paid.

This design is not legal advice. Whether operating it requires a money transmitter or payment institution licence, and which limits apply, depends on the operator, the countries served and the processor setup, and needs review by counsel before handling real money.

## 9. Running it

| Variable | Default | Notes |
|---|---|---|
| `OPOSSUM_MASTER_KEY` | unset (Opossum off) | 32+ random bytes, base64url: `python -m aiproxy gen-opossum-key`. Keep it secret and backed up: losing it makes receipts unverifiable against new keys and the identity vault unreadable. |
| `OPOSSUM_FEE_PERCENT` | `3` | default fee |
| `OPOSSUM_PROCESSOR_FEE_PERCENT` / `OPOSSUM_PROCESSOR_FEE_FLAT` | `2.9` / `0.30` | processor fee as quoted to users |
| `OPOSSUM_CURRENCIES` | `USD,EUR,GBP,CAD,AUD` | two-decimal currencies |
| `OPOSSUM_SANDBOX_ENABLED` / `OPOSSUM_SEED_SANDBOX_RECIPIENTS` | `true` / `true` | test-money recipients for trying the flow |
| `OPOSSUM_REQUIRE_MFA` | `true` | authenticator required for payments |
| `OPOSSUM_UNVERIFIED_TX_LIMIT`, `OPOSSUM_UNVERIFIED_DAILY_LIMIT`, `OPOSSUM_VERIFIED_TX_LIMIT`, `OPOSSUM_RETENTION_DAYS` | `500`, `1000`, `10000`, `1825` | defaults where no jurisdiction row exists |
| `OPOSSUM_BLOCKED_COUNTRIES` | `CU,IR,KP,SY` | review against the programmes that apply to you |
| `OPOSSUM_PAYMENTS_PER_HOUR` | `20` | per account |
| `OPOSSUM_OFAC_ENABLED` / `OPOSSUM_OFAC_REFRESH_HOURS` | `true` / `24` | automatic OFAC SDN list |
| `OPOSSUM_STRIPE_IDENTITY` / `OPOSSUM_IDENTITY_SELFIE` | `true` / `false` | identity checks through Stripe Identity |

### Real money with Stripe Connect

1. In the Stripe dashboard, enable **Connect** (platform profile, Express accounts).
2. Keep the existing webhook (`/stripe/webhook`) with the events listed in §9a. Opossum payments share it, recognised by `metadata.purpose = opossum_payment`.
3. In `/admin` → **opossum**:
   - add a recipient with processor *stripe connect*;
   - click **stripe onboarding**; the merchant completes Stripe's identity and bank checks;
   - issue them a **merchant key**.
4. The merchant uses the merchant API:
   - `GET /opossum/merchant/api/payments` shows their view of payments;
   - `POST /opossum/merchant/api/invoices` creates an invoice; the customer pays it at `/opossum#pay/invoice/<id>`.

## 9a. Integrations with outside systems

### Stripe: real money

- **Your own business as a recipient.** Create a recipient with processor **stripe** and Stripe account **platform**. Payments are plain Checkout charges to the platform's Stripe account; no Connect needed. The Opossum fee is part of what you keep.
- **Other businesses.** Create a recipient with processor stripe, then click **stripe onboarding**. Stripe Connect Express verifies the business and its bank. The recipient stays in *onboarding* and is not listed until Stripe reports that charges and payouts are enabled. The relay checks every 5 minutes, or on **check stripe**. This needs Connect enabled on the platform account.
- **Refunds.**
  - From the admin (**refund** on a relay payment) or the merchant API (`POST /opossum/merchant/api/payments/{id}/refund`).
  - A Connect refund also reverses the transfer and Opossum's application fee, so nobody keeps money for an undone payment.
  - A refund made directly in the Stripe dashboard arrives as `charge.refunded` and is mirrored.
- **Webhook.** The existing endpoint `/stripe/webhook` now handles these events:
  - `checkout.session.completed`
  - `checkout.session.async_payment_succeeded`
  - `checkout.session.expired`
  - `charge.refunded`
  - `identity.verification_session.verified`
  - `identity.verification_session.requires_input`
  - `identity.verification_session.canceled`

### Stripe Identity

The **privacy** room shows **verify with stripe identity** once a legal name and address are saved. Stripe's hosted page checks the document (live capture; set `OPOSSUM_IDENTITY_SELFIE=true` to also require a matching selfie). The signed webhook then marks the account verified, which raises the payment limit. A sanctions match still wins: a verified person on the list stays in review. Identity must be activated in the Stripe dashboard; until it is, the app says so.

### OFAC sanctions list

- **Source:** `SDN.CSV` and `ALT.CSV` from OFAC's Sanctions List Service, with the older treasury.gov paths as fallback.
- **Refresh:** within a minute of start-up, then every `OPOSSUM_OFAC_REFRESH_HOURS` (24); or on demand with **refresh now** in the admin.
- **Safety on failure:** a failed or suspiciously small download never replaces the loaded list, and the error is shown in the admin.
- **Matching:** names become sets of words, ignoring case, accents, punctuation and initials. A listed name matches when all of its words (two or more) appear in the person's name in any order. This is a filter for human review, not a verdict.

### Crypto: stablecoins through Stripe, and direct on-chain payments

There are two ways to take crypto, and **Opossum never holds anyone's coins or keys** in either.

**1. Stablecoins through Stripe.** When "Stablecoins and crypto" is on in the Stripe dashboard (Payment methods), Stripe Checkout offers USDC (Ethereum, Solana, Polygon, Base) next to cards for USD payments. Nothing to configure in Opossum. Stripe settles it to the account in dollars, and the receipt records `payment_method: stablecoin via Stripe`, the network and the transaction hash.

**2. Direct on-chain, to the merchant's own wallet.** The merchant (or the operator in the admin) gives:

- a **Bitcoin extended public key** (xpub, ypub or zpub) plus the **first receiving address** their wallet shows. The relay derives address 0 and refuses the setup unless it matches, so a wrong key type can never send customers' coins somewhere the wallet does not watch. Private keys (xprv) are refused;
- and/or a **USDC receiving address** (0x…, checksum verified), used on Ethereum, Base, Polygon, Arbitrum and Optimism.

`PUT /opossum/merchant/api/chain {"btc_xpub": "zpub…", "btc_first_address": "bc1q…", "usdc_address": "0x…"}` (admin: `PUT /admin/api/opossum/recipients/{id}/chain`).

How a payment works:

- **Bitcoin.** Each payment gets a fresh address (m/0/1, m/0/2, … of the merchant's key), so payments are not linked by address reuse. The price comes from a BTC-USD spot quote and is held for `OPOSSUM_CHAIN_QUOTE_MINUTES` (30). Settles after `OPOSSUM_BTC_CONFIRMATIONS` (2).
- **USDC.** Sent to the merchant's address. 1 USDC = 1 USD, and each payment's amount carries a unique tail of up to 0.009999 USDC so the relay can match it; one on-chain transfer can never settle two payments. Settles after 12 (Ethereum), 20 (Base, Arbitrum, Optimism) or 64 (Polygon) blocks.
- The payer's app shows the address, the exact amount, a QR code and a wallet link (BIP21 / EIP-681), then follows the payment until it settles and the receipt is signed. The receipt adds the chain, asset, crypto amount, transaction id, deposit address and price used.
- **Fees.** The payer sends the price; the network fee is set by their wallet. Opossum's fee is not taken from the coins (it cannot be: they go straight to the merchant). It accrues to the merchant's `fees_due` (`GET /opossum/merchant/api/fees`) and the operator records payments with `POST /admin/api/opossum/recipients/{id}/fees-paid`.
- **When it goes wrong.**
  - *expired:* the quote ran out with nothing received.
  - *underpaid:* less than quoted arrived before the quote ran out.
  - *received_late:* Bitcoin arrived after the price lock; the merchant decides.
  - *review:* see screening below.

  These never settle automatically.
- **Refunds.** The relay cannot move coins. The merchant sends the refund from their wallet, then records its transaction id: `POST /opossum/merchant/api/payments/{id}/refund {"txid": "…"}`. Opossum's fee on that payment is cancelled.
- **Screening.** The OFAC refresh also loads the crypto addresses the SDN list publishes ("Digital Currency Address - …"). A payment sent from a listed address goes to **review** and is never settled automatically, and the merchant gets a `payment.review` webhook.

What this does **not** do, on purpose:

- No mixing, tumbling, coinjoin or anything else that obscures where funds came from or went.
- No custody: Opossum never holds balances, so it is not a wallet or an exchange.

A public blockchain shows the amount, the sending wallet and the receiving address to anyone, forever. Opossum's privacy on-chain is limited to keeping *who you are* away from the merchant and out of the chain, and keeping your ledger on your device.

**Infrastructure.**

- **Chain data:**
  - Bitcoin is watched through an Esplora API (`OPOSSUM_BTC_API`, default mempool.space).
  - USDC is watched through JSON-RPC nodes (`OPOSSUM_EVM_RPC`, a JSON map of network to one URL or a list tried in order; defaults are public rate-limited endpoints with a fallback each).
  - In production, use your own node or a paid provider.
- **Price:** comes from `OPOSSUM_PRICE_API` (Coinbase spot).
- **Watch cadence:** payments are checked on the maintenance cycle, every 30 s.
- **Turning it off:** set `OPOSSUM_CHAIN_ENABLED=false`.

Whether accepting crypto needs a licence or registration depends on your country and business; that is a question for your lawyer.

### Merchants' systems: signed webhooks

A merchant sets an endpoint with `PUT /opossum/merchant/api/webhook {"url": "https://…"}`; the signing secret is returned once.

- **Events:** `payment.settled`, `payment.refunded`, `payment.review` (on-chain payment held for compliance), `invoice.paid`, `webhook.test`.
- **Delivery:** events are written to an outbox in the same transaction as the payment, then delivered with backoff (10 s up to 12 h, 8 attempts).
- **What they carry:** only the recipient's view of the payment.
- **Address guard:** endpoints must be public https; private, loopback, link-local and reserved addresses are refused, and redirects are not followed.

Verify a delivery like this:

```python
import hmac, hashlib
t, v1 = (part.split("=", 1)[1] for part in request.headers["Opossum-Signature"].split(","))
expected = hmac.new(secret.encode(), t.encode() + b"." + request.body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, v1)   # and reject if int(t) is more than a few minutes old
```

### Accounting software and banks

The ledger exports reports as **OFX 1.02** (imported by QuickBooks, Xero, Quicken, Moneydance and GnuCash) and **QIF** (Quicken), besides CSV, XLSX, PDF and JSON. It imports bank statements as **OFX/QFX** (what most banks offer as "download for Quicken/QuickBooks") or CSV. OFX imports skip transactions already imported, using the bank's FITID. All of this happens on the device.

## 10. API summary

User API (`/opossum/api`, session cookie plus `X-Opossum-Request: 1` on writes):

| Method | Path | Purpose |
|---|---|---|
| GET | `/config`, `/auth/params?email=`, `/recipients`, `/invoices/{id}`, `/data-map` | public information (unknown emails get a stable fake salt) |
| POST | `/quote`, `/verify` | fee breakdown; receipt verification |
| POST | `/accounts`, `/session`, `/recovery`; DELETE `/session` | sign up, sign in (optionally registering this device), recover, sign out |
| GET | `/me`, `/devices`, `/identity`, `/backup`, `/payments`, `/payments/{id}`, `/disclosures` | the account's own data |
| POST / PUT / DELETE | `/mfa/setup`, `/mfa/confirm`, `/mfa/disable`, `/devices`, `/devices/{id}`, `/identity`, `/backup`, `/backup/keys`, `/account/close` | account management |
| POST | `/payments` | a signed payment (`X-Opossum-Device`, `X-Opossum-Signature`) |
| POST | `/identity/verify` | start a Stripe Identity check; returns the hosted verification URL |

Merchant API (`/opossum/merchant/api`, `Authorization: Bearer opm_…`): `GET /me`, `GET /payments`, `POST /payments/{id}/refund` (on-chain: `{"txid"}`), `GET/POST /invoices`, `GET/PUT /webhook`, `PUT /chain`, `GET /fees`.

Compliance API (`/admin/api/opossum`, admin sign-in):

- `overview`, `transactions`
- `recipients` (plus `merchant-key`, `stripe-onboarding`, `check-onboarding`, `chain` and `fees-paid`)
- `transactions/{id}/refund`, `sanctions`, `sanctions/refresh`
- `fee-rules`, `jurisdictions`, `screening`
- `kyc`, `cases` (plus `disclose` and `close`)
- `audit`, `audit/verify`, `limits/{country}`

## 11. Honest limits of this MVP

- **Audit.** The cryptography uses established primitives through `pyca/cryptography` and WebCrypto, but it has not been independently audited. That must happen before real funds flow.
- **Processor.** Stripe (cards and, where enabled, stablecoins) is the card processor. Direct on-chain payments cover Bitcoin and USDC on five EVM networks; there is no bank-transfer rail. On-chain there is no chargeback and the relay cannot refund, and a chain reorganisation deeper than the confirmation count could undo a settled payment.
- **Crypto privacy.** Public blockchains are public. Anyone can follow an on-chain payment between wallets. Opossum does not and will not mix or obscure funds.
- **FX.** No currency conversion: totals and limits are per currency.
- **Payees.** Payments go to onboarded recipients (merchants and payees). Person-to-person transfers between users and receiving money into Opossum are not in the MVP.
- **Refunds and disputes.** Refunds are full refunds only. Disputes (chargebacks) are handled in the Stripe dashboard.
- **Sanctions lists.** OFAC is loaded automatically. UN, EU and UK lists must be loaded through the admin API if you operate there. Matching is word-based, not phonetic.
- **Relay trust.** The relay operator, holding the master key, can technically link a payment to an account; that link is needed for fraud, disputes and the law. Routine staff views do not show it, opening it is recorded, and recipients never get it. Opossum does not claim otherwise.
