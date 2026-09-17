# Content Fingerprints

Task 11 records normalized HTML, visible-text, favicon, and indicator evidence.

## Indicators

- Gambling terms such as casino, betting, rummy, sportsbook, and odds.
- Payment terms such as UPI, Paytm, deposit, withdraw, crypto, and USDT.
- India-targeting terms such as INR, IPL, cricket, IMPS, and NEFT.

The terms and occurrence counts are evidence for analyst review, not legal conclusions.

## How fingerprinting works

For HTML responses, the collector keeps the raw response hash, then creates a
normalized HTML hash after removing comments, scripts, styles, templates, id,
nonce, and data-prefixed attributes. It also stores a visible-text hash after
whitespace normalization.

The raw HTML, content-fingerprint JSON, and favicon when present are included
in the immutable evidence package and its manifest. The case workspace
aggregates observed indicator terms in the Content indicators panel.

## Favicon safeguards

An icon declared in the HTML is collected only when it is same-origin.
Otherwise the collector attempts /favicon.ico at the collected page host.
Redirect-following is disabled and files larger than 1 MiB are ignored. This
avoids arbitrary third-party fetches through a page icon reference.

## Correlation

The Task 10 content pivot now prefers exact normalized-HTML hashes, but falls
back to historic raw-content hashes for older observations. Exact matches are
investigative leads: common templates, parked pages, and CDN error pages can
still produce weak relationships.
