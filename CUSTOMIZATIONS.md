# Cazi Agent Customizations

This fork keeps the upstream Komari agent protocol compatible while adding:

- HTTP transport reachability independent from HTTP status health;
- bounded multi-sample ICMP, TCP and HTTP probes;
- configurable ICMP payload size and per-task DNS resolver;
- DNS, connect, TLS, TTFB, loss, jitter and min/max/average timing details;
- connection-level Linux TCP retransmission counts through `TCP_INFO`;
- privacy-safe resolved-address fingerprints instead of uploading raw target IPs;
- self-updates from `cazi-cc/komari-agent`.

The weekly `Sync Upstream` workflow creates a review PR and never deploys or merges
upstream changes automatically.
