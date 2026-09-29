"""Opossum Protocol: privacy-preserving transaction relay and personal ledger.

Three layers are kept apart:

* moving money: the relay hands a minimal payment instruction to an
  established processor (Stripe Connect, or the clearly labelled sandbox);
* proving and accounting for money: signed, selectively disclosable
  receipts, and a ledger that lives encrypted on the user's device;
* revealing identity: an encrypted identity vault that recipients never see
  and that is only opened for a recorded, legally grounded compliance case.

See docs/opossum.md for the architecture, data map and threat model.
"""
