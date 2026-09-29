"""Sanctions screening against the US Treasury's official OFAC lists.

Loads the Specially Designated Nationals list (SDN.CSV) and its alternate
names (ALT.CSV) from OFAC's Sanctions List Service, refreshes them daily,
and re-screens every identity in the vault and every recipient after each
refresh. A match never blocks silently: the account or recipient goes to
review, payments pause, and a compliance officer decides in the admin.

Matching: names are reduced to sets of words (case, accents and punctuation
removed; one-letter initials dropped). A person matches a listed name when
all the words of that listed name (two or more) appear in their name, in
any order, so "SMITH, John" matches "John Michael Smith". This is a
screening filter that sends people to human review, not a verdict.

Other lists (UN, EU, UK) can be loaded through the admin API in the same
way; which lists apply depends on where the operator does business.
"""

from __future__ import annotations

import csv
import io
import re
import itertools
import logging
from datetime import timedelta

import httpx
from sqlalchemy import delete, insert, select

from ..models import utcnow
from ..services import Services
from . import audit
from .compliance import normalise_name
from .models import OpAccount, OpIdentity, OpListMeta, OpRecipient, OpScreeningEntry

log = logging.getLogger("aiproxy.opossum")

LIST_NAME = "ofac-sdn"
ADDRESS_LIST = "ofac-sdn-crypto-addresses"
COMMENTS_URLS = (
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_COMMENTS.CSV",
    "https://www.treasury.gov/ofac/downloads/sdn_comments.csv",
)
DIGITAL_ADDRESS = re.compile(r"Digital Currency Address - ([A-Z0-9]{2,8})\s+([A-Za-z0-9]{20,110})")
SDN_URLS = (
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
    "https://www.treasury.gov/ofac/downloads/sdn.csv",
)
ALT_URLS = (
    "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ALT.CSV",
    "https://www.treasury.gov/ofac/downloads/alt.csv",
)
MAX_SUBSET_WORDS = 7


def key_for(name: str) -> str:
    """Sorted set of words; the form stored and looked up."""
    words = {w for w in normalise_name(name).split() if len(w) > 1}
    return " ".join(sorted(words))


def candidate_keys(name: str) -> list[str]:
    """Every combination of two or more of the name's words."""
    words = sorted({w for w in normalise_name(name).split() if len(w) > 1})[:MAX_SUBSET_WORDS]
    out = []
    for size in range(2, len(words) + 1):
        out.extend(" ".join(c) for c in itertools.combinations(words, size))
    return out


async def screen(session, name: str) -> str | None:
    """The list a name matches, or None."""
    keys = candidate_keys(name)
    if not keys:
        return None
    return await session.scalar(select(OpScreeningEntry.list_name).where(OpScreeningEntry.normalized_name.in_(keys)).limit(1))


def _field(value: str) -> str:
    value = (value or "").strip()
    return "" if value in ("-0-", "-0- ") else value


def parse_sdn(text: str) -> list[str]:
    """SDN.CSV columns: ent_num, SDN_Name, SDN_Type, Program, ... (no header row)."""
    names = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and _field(row[1]) and _field(row[0]).isdigit():
            names.append(_field(row[1]))
    return names


def parse_alt(text: str) -> list[str]:
    """ALT.CSV columns: ent_num, alt_num, alt_type, alt_name, alt_remarks."""
    names = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 4 and _field(row[3]) and _field(row[0]).isdigit():
            names.append(_field(row[3]))
    return names


def address_key(address: str) -> str:
    """0x and bech32 addresses are case-insensitive; base58 ones are not."""
    a = address.strip()
    if a.lower().startswith(("0x", "bc1")):
        a = a.lower()
    return "addr:" + a


def parse_addresses(*texts: str) -> list[str]:
    """Crypto addresses OFAC lists in the SDN remarks ("Digital Currency Address - XBT bc1...")."""
    out = set()
    for text in texts:
        for _, address in DIGITAL_ADDRESS.findall(text or ""):
            out.add(address)
    return sorted(out)


async def screen_addresses(session, addresses: list[str]) -> str | None:
    keys = [address_key(a) for a in addresses if a]
    if not keys:
        return None
    return await session.scalar(select(OpScreeningEntry.list_name).where(OpScreeningEntry.normalized_name.in_(keys)).limit(1))


async def load_addresses(services: Services, addresses: list[str], source: str) -> int:
    keys = sorted({address_key(a)[:200] for a in addresses})
    async with services.db.session() as session, session.begin():
        await session.execute(delete(OpScreeningEntry).where(OpScreeningEntry.list_name == ADDRESS_LIST))
        if keys:
            await session.execute(insert(OpScreeningEntry), [{"normalized_name": k, "list_name": ADDRESS_LIST} for k in keys])
        meta = await session.get(OpListMeta, ADDRESS_LIST)
        if meta is None:
            meta = OpListMeta(list_name=ADDRESS_LIST, source=source)
            session.add(meta)
        meta.source, meta.entries, meta.loaded_at, meta.checked_at, meta.last_error = source[:300], len(keys), utcnow(), utcnow(), None
        await audit.append(session, "system", "screening_list_loaded", ADDRESS_LIST, entries=len(keys))
    return len(keys)


async def _download(services: Services, urls: tuple[str, ...]) -> tuple[str, str]:
    last = "no source"
    for url in urls:
        try:
            resp = await services.http.get(url, timeout=60.0, follow_redirects=True)
            if resp.status_code == 200 and len(resp.content) > 1000:
                return resp.content.decode("utf-8", errors="replace"), url
            last = f"{url}: HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            last = f"{url}: {type(exc).__name__}"
    raise RuntimeError(last)


async def load_names(services: Services, list_name: str, names: list[str], source: str) -> int:
    keys = sorted({k for k in (key_for(n) for n in names) if " " in k})
    async with services.db.session() as session, session.begin():
        await session.execute(delete(OpScreeningEntry).where(OpScreeningEntry.list_name == list_name))
        for start in range(0, len(keys), 1000):
            await session.execute(insert(OpScreeningEntry), [{"normalized_name": k[:200], "list_name": list_name} for k in keys[start:start + 1000]])
        meta = await session.get(OpListMeta, list_name)
        if meta is None:
            meta = OpListMeta(list_name=list_name, source=source)
            session.add(meta)
        meta.source, meta.entries, meta.loaded_at, meta.checked_at, meta.last_error = source[:300], len(keys), utcnow(), utcnow(), None
        await audit.append(session, "system", "screening_list_loaded", list_name, entries=len(keys), source=source[:120])
    return len(keys)


async def refresh_ofac(services: Services) -> dict:
    """Download SDN + alternate names and replace the list. Keeps the old list on failure."""
    try:
        sdn_text, sdn_url = await _download(services, SDN_URLS)
        alt_text, _ = await _download(services, ALT_URLS)
        names = parse_sdn(sdn_text) + parse_alt(alt_text)
        if len(names) < 1000:
            raise RuntimeError(f"only {len(names)} names parsed; refusing to replace the list")
    except RuntimeError as exc:
        async with services.db.session() as session, session.begin():
            meta = await session.get(OpListMeta, LIST_NAME)
            if meta is None:
                meta = OpListMeta(list_name=LIST_NAME, source=SDN_URLS[0])
                session.add(meta)
            meta.last_error, meta.checked_at = str(exc)[:300], utcnow()
        log.error("OFAC list refresh failed: %s", exc)
        return {"ok": False, "error": str(exc)}
    count = await load_names(services, LIST_NAME, names, sdn_url)
    try:
        comments, _ = await _download(services, COMMENTS_URLS)
    except RuntimeError:
        comments = ""  # the remarks overflow file is optional
    address_count = await load_addresses(services, parse_addresses(sdn_text, comments), sdn_url)
    hits = await rescreen(services)
    log.info("OFAC list loaded", extra={"event": "ofac_loaded", "entries": count, "crypto_addresses": address_count, "matches": hits})
    return {"ok": True, "entries": count, "crypto_addresses": address_count, "new_matches": hits}


async def rescreen(services: Services) -> int:
    """Screen every vault identity and recipient again. Returns new matches."""
    from .web import keys as get_keys

    k = get_keys(services)
    hits = 0
    async with services.db.session() as session, session.begin():
        rows = (await session.execute(select(OpAccount, OpIdentity).join(OpIdentity, OpIdentity.account_id == OpAccount.id)
                                      .where(OpAccount.status == "active", OpAccount.kyc_status != "review"))).all()
        for account, identity in rows:
            name = k.open(identity.ciphertext, f"op_identities:{account.id}:doc").get("legal_name")
            hit = await screen(session, name or "")
            if hit:
                account.kyc_status, account.kyc_note, account.kyc_updated_at = "review", f"screening match ({hit})", utcnow()
                await audit.append(session, "compliance", "screening_match", None, list=hit, account_ref=k.owner_tag(account.id)[:12])
                hits += 1
        for recipient in (await session.execute(select(OpRecipient).where(OpRecipient.status == "active"))).scalars():
            hit = await screen(session, recipient.display_name)
            if hit:
                recipient.status = "review"
                await audit.append(session, "compliance", "recipient_screening_match", recipient.handle, list=hit)
                hits += 1
    return hits


async def due(services: Services) -> bool:
    if not services.settings.opossum_ofac_enabled:
        return False
    async with services.db.session() as session:
        meta = await session.get(OpListMeta, LIST_NAME)
    last = meta.checked_at if meta else None
    if last is None:
        return True
    last = last if last.tzinfo else last.replace(tzinfo=utcnow().tzinfo)
    return utcnow() - last >= timedelta(hours=services.settings.opossum_ofac_refresh_hours)
