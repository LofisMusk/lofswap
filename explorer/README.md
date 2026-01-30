Lofswap Explorer (static)

This folder contains a standalone static explorer page.

What it expects
- An Explorer HTTP API that exposes the same read-only endpoints used by the old in-node explorer:
  /health
  /telemetry
  /height
  /chain
  /chain/latest-tx
  /block/{hash}
  /mempool
  /peers
  /peers/status
  /address/{addr}/balance
  /address/{addr}/txs

How to host
1) Copy `explorer/index.html` to your Apache web root.
2) Point the page to an API base:
   - Add a query param: `?api=https://host:port`, or
   - Leave it empty if the API is on the same origin (recommended for HTTPS).

CORS note
If the API is on a different domain or port, it must send CORS headers. The simplest setup is to
reverse-proxy the API under the same Apache host so the page can call `/health`, `/chain`, etc.

Defaults
The page defaults to same-origin (empty base) so it works behind a reverse proxy on HTTPS.
