# Claude Code Prompt: `root_server_path_gtrace`

Add a new dns-mcp tool called `root_server_path_gtrace` to the existing FastMCP server.

This tool runs gtrace (https://github.com/hervehildenbrand/gtrace) against a root
server IP and correlates the resulting path analysis with a DNS timing probe to
the same target.

gtrace provides MPLS/ECMP-aware path analysis with MTR mode and GlobalPing integration.
This tool shells out to `gtrace` if available, falls back to standard `traceroute`
with a clear flag in the response if not.

Steps:
1. Resolve target root letter to canonical IP from the hardcoded IANA list.
2. Run a CHAOS TXT query for timing and instance ID (same as root_server_latency).
3. If gtrace is available in PATH:
   - Run: `gtrace --json <target-ip>` (or nearest equivalent for JSON output — check
     gtrace's --help for the correct flag)
   - Parse JSON output: hop list, MPLS labels if present, ECMP paths if detected, RTTs
   - Note if multiple ECMP paths were observed to the same hop (significant for
     anycast path analysis — ECMP can explain why traceroute and DNS land on different
     instances)
4. If gtrace unavailable, fall back to subprocess traceroute with the same parsing
   logic as root_path_analysis.
5. Correlate: compare last-hop RTT from path tool vs DNS query RTT. A large gap
   (>10ms) may indicate the DNS query took a different ECMP path than the traceroute.

Parameters:
- letter: str  # a-m
- ip_version: Literal["ipv4", "ipv6"] = "ipv4"
- max_hops: int = 20
- timeout: float = 10.0  # gtrace can be slower than plain traceroute

Return: letter, root IP, DNS RTT ms, CHAOS instance string, gtrace_available bool,
hop list with MPLS/ECMP annotations where present, ECMP_paths_detected bool,
RTT_correlation_gap_ms (DNS RTT minus final-hop RTT, signed), and a path_summary
string.

Hard wall-clock timeout on subprocess. If gtrace errors or returns non-zero exit,
capture stderr and include in the response as `gtrace_error`. Follow existing
FastMCP/Pydantic patterns.
