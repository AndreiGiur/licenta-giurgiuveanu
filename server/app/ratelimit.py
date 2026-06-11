"""Rate limiting global cu slowapi.

Folosit pe endpoint-urile sensibile (login, register) pentru a preveni
atacurile brute-force. Cheia limitatorului este adresa IP a clientului.
Cand limita e depasita, slowapi raspunde cu HTTP 429 Too Many Requests.

In teste, rate limiting-ul se dezactiveaza prin env `DISABLE_RATELIMIT=true`
(setat in conftest.py) pentru a nu afecta testele cu multe requesturi rapide.

Limitare asumata: storage-ul e in-memory per proces (default slowapi), deci
la rulare multi-worker limita efectiva = limita * numar workeri. Aceeasi
asumptie single-worker ca la `livestate.py`; pentru multi-worker s-ar trece
pe storage partajat (ex: Redis, `storage_uri="redis://..."`).
"""
import os

from slowapi import Limiter
from slowapi.util import get_remote_address


_ratelimit_enabled = os.getenv("DISABLE_RATELIMIT", "").lower() != "true"


limiter = Limiter(key_func=get_remote_address, enabled=_ratelimit_enabled)
