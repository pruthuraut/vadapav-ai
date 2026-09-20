---
name: bb-harness-js-recon
description: Analyze authorized JavaScript discovered by a completed bb-harness recon session. Consume domain-scoped javascript.txt, live-urls.txt, urls.txt, and raw recon artifacts; collect current and historical JS URLs, download and beautify bounded in-scope files, extract endpoints/source maps, scan locally for possible secrets, and save reviewable outputs. Use when the user asks for JavaScript reconnaissance, bundle analysis, LinkFinder, SecretFinder, source maps, or JS exposure review.
---

# bb-harness JavaScript recon

This skill runs after the single `bb-harness-recon` skill. It does not replace
normal recon, and it never invents a target or expands scope. All work is
limited to the authorized domain recorded in the selected recon manifest.

## Required input

Select one completed recon session:

```text
output/recon/<domain>/<session_id>/manifest.json
```

Required handoff files:

- `javascript.txt`: JS URLs already found by recon.
- `live-urls.txt`: URLs validated by ProjectDiscovery `httpx`, when available.
- `urls.txt`: complete discovered URL inventory, including historical URLs.
- `manifest.json`: target, normalized domain, session, and execution metadata.

If these files are absent, stop and ask the operator to run the normal recon
skill first. Do not substitute a new target or scrape arbitrary URLs.

## Output layout

Write only inside the selected session:

```text
output/recon/<domain>/<session_id>/javascript/
├── js-urls.txt                 # deduplicated current + historical JS URLs
├── live-js.txt                 # HTTP 200/206/304 JS responses
├── downloaded/                 # authorized JS response bodies
├── beautified/                 # readable copies; originals preserved
├── source-maps.txt             # discovered .map URLs
├── endpoints.txt               # LinkFinder/xnLinkFinder output
├── parameters.txt              # candidate parameters/routes
├── possible-secrets.txt        # unverified local pattern matches
├── js-exposures.txt            # preliminary Nuclei results
├── tool-output/                # stdout/stderr from each command
├── manifest.json
└── README.md
```

Never write downloaded JS, cookies, HAR files, tokens, or credentials into the
repository. `output/` is runtime data and remains Git-ignored.

## Workflow

### 1. Validate and assemble the URL set

Use the selected session’s files only. Preserve provenance in the manifest:
`recon_current`, `recon_historical`, `wayback_cdx`, `waybackurls`, `gau`, or
`subjs`.

```bash
DOMAIN="example.com"
SESSION_DIR="output/recon/$DOMAIN/<session_id>"
JS_DIR="$SESSION_DIR/javascript"
mkdir -p "$JS_DIR" "$JS_DIR/downloaded" "$JS_DIR/beautified" "$JS_DIR/tool-output"

# Existing recon output is the primary source.
cat "$SESSION_DIR/javascript.txt" "$SESSION_DIR/live-urls.txt" "$SESSION_DIR/urls.txt" 2>/dev/null \
  | grep -Ei '\.js([?#].*)?$' | sort -u > "$JS_DIR/js-urls.txt"
```

Keep query strings because versioned bundles and cache-busting parameters can
identify distinct assets. Redact sensitive query values only in reports, not
when making an authorized read-only request to the same in-scope URL.

### 2. Add historical JS URLs

Historical collection is allowed only for the same authorized domain:

```bash
echo "$DOMAIN" | waybackurls \
  | grep -Ei '\.js([?#].*)?$' | sort -u >> "$JS_DIR/js-urls.txt"

curl -s "https://web.archive.org/cdx/search/cdx?url=*.$DOMAIN/*&collapse=urlkey&output=text&fl=original&filter=original:.*\\.js([?].*)?$" \
  | grep -Ei '^https?://.*\.js([?#].*)?$' >> "$JS_DIR/js-urls.txt"

sort -u "$JS_DIR/js-urls.txt" -o "$JS_DIR/js-urls.txt"
```

`waymore`, `gau`, and `subjs` may be used if installed, but missing optional
collectors are recorded as skipped. Do not query another organization or a
third-party hostname merely because it appears inside a script.

### 3. Filter live JS URLs

Prefer the same container-first tool policy as normal recon:

```bash
httpx -l "$JS_DIR/js-urls.txt" -silent -mc 200,206,304 \
  -follow-redirects -status-code -title -tech-detect \
  | tee "$JS_DIR/live-js.txt"
```

If `httpx` is unavailable, use the existing `live-urls.txt` intersection and
record that live filtering was incomplete. Do not silently treat every
historical JS URL as live.

### 4. Download authorized JS bodies

Download only URLs in `live-js.txt`, with a bounded request count, timeout,
rate, and response-size limit. Preserve the URL-to-file mapping in
`download-manifest.json` and keep response bodies separate from tool logs.

Preferred tools, in order:

```bash
# If supported by the installed httpx version, store response bodies locally.
httpx -l "$JS_DIR/live-js.txt" -silent -sr -srd "$JS_DIR/downloaded" \
  -timeout 20 -rl 5

# Otherwise use a bounded downloader with one URL per request.
wget --timeout=20 --tries=1 --max-redirect=3 --no-verbose \
  --directory-prefix="$JS_DIR/downloaded" -i "$JS_DIR/live-js.txt"
```

Do not upload files, execute downloaded JavaScript, use extracted credentials,
or send callbacks. A failed download is an observation, not a finding.

### 5. Beautify and inspect source maps

Preserve originals, then create readable copies:

```bash
find "$JS_DIR/downloaded" -type f -iname '*.js' -print0 \
  | xargs -0 -r -n1 js-beautify -o "$JS_DIR/beautified/"

grep -RhoE 'https?://[^"'"'"' ]+\.map|[^"'"'"' ]+\.js\.map' "$JS_DIR/downloaded" \
  | sort -u > "$JS_DIR/source-maps.txt"
```

Check common bundles (`main.js`, `app.js`, hashed Webpack/Vite bundles), map
files, comments, internal hostnames, staging references, and route strings.
Beautification is readability assistance only; minification is not encryption.

### 6. Extract endpoints and parameters

Run extraction locally against downloaded files:

```bash
python3 LinkFinder/linkfinder.py -i "$JS_DIR/downloaded" -o cli \
  > "$JS_DIR/endpoints.txt"

# If installed, use the Go implementation as a second opinion.
xnLinkFinder -i "$JS_DIR/downloaded" -o "$JS_DIR/endpoints-xnlinkfinder.txt"

grep -RhoE '(/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+)' "$JS_DIR/beautified" \
  | sort -u > "$JS_DIR/parameters.txt"
```

Classify results for manual review: undocumented APIs, admin/internal/debug
routes, GraphQL operations, upload/download routes, hidden parameters,
third-party services, source-map paths, and environment references.

### 7. Search for possible secrets locally

These are leads only. Never authenticate with, validate, or exfiltrate an
extracted value:

```bash
grep -RniE \
  'api[_-]?key|apikey|access_token|secret[_-]?key|client_secret|password|auth[_-]?token|bearer|AWS_ACCESS|AWS_SECRET|ghp_|ghs_|eyJ[A-Za-z0-9]|sk-[A-Za-z0-9]+|PRIVATE_KEY' \
  "$JS_DIR/beautified" 2>/dev/null | tee "$JS_DIR/possible-secrets.txt"

trufflehog filesystem "$JS_DIR/downloaded" --only-verified --json \
  > "$JS_DIR/trufflehog.json" 2> "$JS_DIR/tool-output/trufflehog.stderr.txt"
```

Redact values in summaries. Record file, line, pattern category, and confidence,
not the secret itself.

### 8. Scale exposure review with Nuclei

Only use read-only templates and the authorized JS URL list:

```bash
nuclei -l "$JS_DIR/live-js.txt" -t ~/nuclei-templates/exposures/ \
  -severity info,low,medium,high,critical \
  -rate-limit 5 -c 5 -o "$JS_DIR/js-exposures.txt"
```

Nuclei output is preliminary. Manually reproduce only within scope and follow
the project’s evidence rules before treating anything as confirmed.

## Review checklist

- [ ] Current and historical JS URLs are deduplicated and source-labeled.
- [ ] Live filtering is complete or explicitly marked incomplete.
- [ ] Originals and beautified copies are both retained.
- [ ] `main.js`, `app.js`, hashed bundles, and `.map` candidates were reviewed.
- [ ] Endpoints, parameters, admin/debug routes, uploads, and auth routes were extracted.
- [ ] Possible secrets are redacted and remain unverified.
- [ ] No credentials were used and no out-of-scope host was requested.
- [ ] Nuclei results are manually reviewed before reporting.

## Completion report

Write `javascript/README.md` with target/session, timestamps, counts, tools
available, skipped tools, URL sources, download failures, output paths, and
limitations. Clearly distinguish discovered, downloaded, parsed, possible
secret, exposure, needs-review, and confirmed states.
