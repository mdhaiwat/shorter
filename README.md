[![Go Report Card](https://goreportcard.com/badge/github.com/7i/shorter)](https://goreportcard.com/report/github.com/7i/shorter)
![Linux](https://img.shields.io/badge/Supports-Linux-green.svg)
![windows](https://img.shields.io/badge/Supports-windows-green.svg)
[![License](https://img.shields.io/badge/License-UNLICENSE-blue.svg)](https://raw.githubusercontent.com/7i/shorter/master/UNLICENSE)
[![License](https://img.shields.io/badge/License-0BSD-blue.svg)](https://raw.githubusercontent.com/7i/shorter/master/LICENSE)
# shorter
URL shortener with pastebin and QR code support


## WIP

This project is a *work in progress*. The implementation is *incomplete* and subject to change.

If you want to try to run shorter, please set your correct values in the config before starting the server.

Shortened links on the pre alpha version test site 7i.se will be cleared from time to time during testing without notice.

## Installation

```bash
go get github.com/7i/shorter
```

## Usage

```bash
shorter /path/to/config
```

## Features

### URL shortening

Create a short link via the web UI or the quick-add GET syntax:

```bash
# Quick-add: shortest available key
7i.se?https://www.example.com

# Quick-add: custom key
7i.se/mykey?https://www.example.com
```

Four key buckets, each with a configurable timeout:

| Length | Example | Default timeout |
|--------|---------|-----------------|
| 1 char | `7i.se/a` | 24 h |
| 2 chars | `7i.se/ab` | 7 d |
| 3 chars | `7i.se/abc` | 60 d |
| Custom (4–64 chars) | `7i.se/mykey` | 30 d |

Append `~` to any key to preview where it points without consuming an access (`7i.se/a~`).

### Pastebin

Submit a text blob via the web UI (`requestType=text`). Large blobs are transparently gzip-compressed before storage.

### QR codes

```
GET /qr/{key}
```

Returns a 256×256 PNG QR code encoding the full short URL for the given key.

### JSON API

#### Shorten a URL

```
POST /api/v1/shorten
Content-Type: application/json

{
  "url":    "https://www.example.com",
  "len":    "1",          // "1", "2", "3", or "custom"
  "key":    "mykey",      // optional, required when len=custom
  "x_times": 5            // optional: delete after N accesses (0 = unlimited)
}
```

Response `201 Created`:
```json
{
  "key":       "a",
  "short_url": "https://7i.se/a",
  "expires":   "Mon 2025-01-01 12:00 UTC"
}
```

#### Look up a key (no access consumed)

```
GET /api/v1/lookup/{key}
```

Response `200 OK`:
```json
{
  "key":             "a",
  "link_type":       "url",
  "url":             "https://www.example.com",
  "expires":         "Mon 2025-01-01 12:00 UTC",
  "access_count":    42,
  "times_remaining": -1
}
```

`times_remaining: -1` means unlimited accesses.

### Persistence

Links are stored in a [bbolt](https://github.com/etcd-io/bbolt) embedded database (`shorterdata/shorter.db`). They survive server restarts and are pruned automatically on startup when expired.

### Admin endpoint

```
GET /listactive~
```

HTTP Basic Auth required. Password is verified as `sha256(password + Salt) == HashSHA256` using constant-time comparison.

### Rate limiting

POST requests are rate-limited to **30 per minute per IP** (sliding window). Exceeding the limit returns `429 Too Many Requests`.

### Blocklist

Domains can be blocked via:
- `BlockedDomains` list in the config file
- An optional newline-delimited `BlocklistFile` (lines starting with `#` are comments)

Blocked URLs return `403 Forbidden`.

## Security

- TLS 1.2+ with AEAD-only cipher suites (AES-GCM, ChaCha20-Poly1305), X25519 curve preferred
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` on all responses
- Optional `Strict-Transport-Security`, `Content-Security-Policy`, and `Report-To` headers
- Decompression bomb protection: 20 MiB hard cap on gzip decompression
- All URL inputs validated; only `http://` and `https://` schemes accepted
- Concurrent-safe link storage with no data races (verified with `-race`)

## TODO
- [x] Implement shortening of URLs
   - [x] 1 char long - configurable timeout
   - [x] 2 chars long - configurable timeout
   - [x] 3 chars long - configurable timeout
   - [x] make timeouts configurable
   - [x] temporary word bindings (7i.se/coolthing)
   - [x] quick add link via GET request with syntax 7i.se?https://example.com
   - [x] quick add word bindings link via GET request with syntax 7i.se/coolthing?https://example.com
   - [x] optional removal of link after N accesses (x_times)
- [x] Add functionality to print where a link is pointing by adding ~ at the end of the link
- [x] Add config file that specifies relevant options
- [x] Pastebin functionality with same timeouts as above
- [x] Move to SSL with Let's Encrypt
- [x] Save all active links in a database file (bbolt)
- [x] JSON REST API for programmatic shortening and lookup
- [x] QR code generation per short link
- [x] Click analytics (access count per link)
- [x] URL deduplication (repeated submissions return existing key)
- [x] Per-IP rate limiting
- [x] Blocklist support (config + file)
- [x] Enable CSP
   - [x] Move all js and css to separate files and modify html/template files to use these
   - [ ] Setup a CSP report collector
- [ ] Add support for subdomains with different configs e.g. d1.7i.se
   - [ ] Add password/client cert protected subdomain management
   - [ ] Let the user managing a subdomain specify generic links and set timeouts
- [ ] Integrate with external malware/blocklist feeds:
   - [ ] https://www.stopbadware.org/firefox
   - [ ] https://www.malwaredomainlist.com
   - [ ] https://isc.sans.edu/suspicious_domains.html
- [ ] Include report form to take down links that break terms of use
- [x] Create Terms of use


## License

The `shorter` project is dual-licensed to the [public domain](UNLICENSE) and under a [zero-clause BSD license](LICENSE). You may choose either license to govern your use of `shorter`.
