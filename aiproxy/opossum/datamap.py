"""What Opossum knows, where it lives, and who can see it.

Served at /opossum/api/data-map and shown in the app's privacy centre. Kept
honest on purpose: anything a processor, bank or the law necessarily
receives is listed as such, never as "not collected".
"""

WHO = ("you", "recipient", "opossum_relay", "payment_processor", "authorities_with_legal_order")

DATA_MAP = {
    "principle": "the system should know what it needs to know, not everything it could know",
    "audiences": list(WHO),
    "items": [
        {
            "data": "ledger: categories, notes, budgets, goals, receipts' private context, manual income and expenses",
            "stored": "on your device, encrypted (AES-256-GCM, key derived from your password); optional backup on Opossum servers as ciphertext only",
            "visible_to": ["you"],
            "retention": "until you delete it",
            "required": "no; it is yours",
        },
        {
            "data": "password",
            "stored": "never leaves your device; the server keeps a scrypt hash of a key derived from it",
            "visible_to": ["you"],
            "retention": "hash kept while the account exists",
            "required": "yes, to sign in",
        },
        {
            "data": "email",
            "stored": "encrypted in the identity vault; accounts are found by a keyed hash of it",
            "visible_to": ["you", "recipient (only if you choose to show it)", "authorities_with_legal_order"],
            "retention": "while the account exists, then only as long as the law requires",
            "required": "yes, to sign in and recover the account",
        },
        {
            "data": "legal name, address, date of birth, phone",
            "stored": "encrypted in the identity vault on Opossum servers",
            "visible_to": ["you", "recipient (only fields you choose, per payment)", "compliance staff (identity checks, recorded)", "authorities_with_legal_order"],
            "retention": "while the account exists, then as long as financial record-keeping law requires",
            "required": "for real-money payments (anti-money-laundering law); not for sandbox payments",
        },
        {
            "data": "payment: transaction ID, amount, currency, fees, status, time, recipient, type",
            "stored": "Opossum relay records",
            "visible_to": ["you", "recipient", "opossum_relay", "payment_processor", "authorities_with_legal_order"],
            "retention": "the retention period of your jurisdiction (default 5 years), then deleted",
            "required": "yes, to move money, settle disputes and meet legal duties",
        },
        {
            "data": "payer pseudonym",
            "stored": "relay record; per-recipient (pseudonymous mode) or single-use (private mode)",
            "visible_to": ["you", "recipient", "opossum_relay"],
            "retention": "with the payment record",
            "required": "yes, so a recipient can reference the payment without knowing who you are",
        },
        {
            "data": "link between a payment and your account",
            "stored": "relay record: a keyed tag (so you can list your receipts) and an encrypted envelope",
            "visible_to": ["opossum_relay (automated)", "compliance staff only through a recorded legal case", "authorities_with_legal_order"],
            "retention": "with the payment record",
            "required": "yes: fraud prevention, disputes and the law require that payments can be traced when legally demanded",
        },
        {
            "data": "identity document and selfie (only if you choose automatic verification)",
            "stored": "at Stripe Identity, never at Opossum; Opossum receives only verified or not, with an opaque reference",
            "visible_to": ["Stripe Identity", "authorities_with_legal_order"],
            "retention": "Stripe's own policy for identity verifications",
            "required": "no; it raises your payment limits",
        },
        {
            "data": "your legal name, compared with sanctions lists",
            "stored": "checked on the relay against the official OFAC list, refreshed daily; a match sends the account to human review",
            "visible_to": ["opossum_relay (automated)", "compliance staff on a match"],
            "retention": "no separate copy is kept",
            "required": "yes, sanctions law",
        },
        {
            "data": "card or bank details",
            "stored": "at the payment processor (Stripe), never at Opossum",
            "visible_to": ["payment_processor", "your bank", "authorities_with_legal_order"],
            "retention": "the processor's own policy",
            "required": "yes, for real-money payments",
        },
        {
            "data": "stablecoin paid through Stripe: network and transaction hash",
            "stored": "at Stripe; the network and transaction hash are also written on your signed receipt",
            "visible_to": ["you", "payment_processor", "anyone reading that blockchain", "authorities_with_legal_order"],
            "retention": "the blockchain keeps it forever; the relay copy with the payment record",
            "required": "yes, if you choose to pay with a stablecoin",
        },
        {
            "data": "on-chain payment (Bitcoin, USDC): amount, your sending wallet, the receiving address, transaction id",
            "stored": "on the public blockchain; the relay keeps the deposit address, amount and transaction id with the payment record",
            "visible_to": ["everyone: public blockchains are public and cannot be made private", "you", "recipient", "opossum_relay",
                           "authorities_with_legal_order"],
            "retention": "the blockchain keeps it forever; the relay copy with the payment record",
            "required": "yes, if you choose to pay from your own wallet. Who you are is never put on the chain or shown to the recipient. "
                        "Opossum does not mix or obscure funds; sending wallets are screened against the OFAC list",
        },
        {
            "data": "private note you chose to commit to a receipt",
            "stored": "only a SHA-256 hash of it (with a secret salt) is sent and signed into the receipt",
            "visible_to": ["you", "anyone you later show the note and salt to"],
            "retention": "hash kept with the receipt",
            "required": "no",
        },
        {
            "data": "IP address and browser",
            "stored": "used for rate limiting in memory; the browser name is kept with your sign-in session only",
            "visible_to": ["opossum_relay", "hosting and network providers"],
            "retention": "sessions end after inactivity; infrastructure logs follow the host's policy",
            "required": "yes, for security",
        },
        {
            "data": "security audit trail",
            "stored": "hash-chained log of security events with opaque IDs only (no names, emails or notes)",
            "visible_to": ["opossum_relay", "compliance staff"],
            "retention": "kept for accountability",
            "required": "yes, to make tampering and misuse detectable",
        },
    ],
    "never": [
        "sell or share data for advertising",
        "send your categories, budgets or notes to anyone",
        "show recipients your identity unless you choose to",
        "open protected data without a recorded legal basis",
    ],
    "legal_disclosure": "when the law requires it, only the fields the order covers are disclosed, each disclosure is recorded, and you are told unless the order forbids it",
}
