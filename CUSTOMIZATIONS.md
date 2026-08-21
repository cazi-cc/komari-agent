# Cazi Agent Customizations

This fork keeps the upstream Komari agent protocol compatible while adding:

- HTTP transport reachability independent from HTTP status health;
- bounded multi-sample ICMP, TCP and HTTP probes;
- configurable ICMP payload size and per-task DNS resolver;
- DNS, connect, TLS, TTFB, loss, jitter and min/max/average timing details;
- connection-level Linux TCP retransmission counts through `TCP_INFO`;
- privacy-safe resolved-address fingerprints instead of uploading raw target IPs;
- separate concurrency gates for latency probes (maximum two) and heavier TCP
  quality/unlock probes (maximum one), protecting monitored workloads from bursts;
- installer dependency mapping that uses Alpine's split `nmap-nping` package
  instead of incorrectly assuming the main `nmap` package contains `nping`;
- self-updates from `cazi-cc/komari-agent`;
- Linux/macOS and Windows installers that resolve releases and binaries only
  from `cazi-cc/komari-agent` by default, including snapshot prereleases.

The weekly `Sync Upstream` workflow creates a review PR and never deploys or merges
upstream changes automatically. `KOMARI_AGENT_REPOSITORY` may override the
distribution repository for controlled testing, but the production default must
remain this fork.
