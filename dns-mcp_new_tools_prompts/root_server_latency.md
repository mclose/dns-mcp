# Claude Code Prompt: `root_server_latency`

Add a new dns-mcp tool called `root_server_latency` to the existing FastMCP server.

This tool queries all 13 DNS root server letters (a through m) for timing and anycast
instance identification. For each root letter:

1. Send a CHAOS TXT query for `hostname.bind` and `id.server` using dnspython, recording
   RTT in milliseconds with sub-millisecond precision (time.perf_counter).
2. Also send a standard A query for `.` (root zone SOA or NS) as a functional check.
3. Return per-letter: letter, operator name, IP (v4 and v6 if available), RTT ms,
   anycast instance string from CHAOS response (or null if not returned), and whether
   the functional query succeeded.

Use the canonical root server IPs from the hardcoded IANA list — do not resolve them
dynamically. Include operator attribution (e.g., Verisign for A/J, ISC for F,
RIPE NCC for K, ICANN for L, etc.).

Parameters:
- ip_version: Literal["ipv4", "ipv6", "both"] = "ipv4"
- timeout: float = 3.0
- include_chaos: bool = True

Return a structured list sorted by RTT ascending. Flag letters where CHAOS returns
nothing (E, G, H are expected to be silent — note this in the docstring as a known
indicator of limited anycast deployment).

Follow existing dns-mcp patterns: Pydantic input model, dnspython for all queries,
Quad9 is the default resolver elsewhere but here we query root IPs directly (not via
a resolver). Handle timeouts and SERVFAIL cleanly — don't let one unresponsive letter
abort the whole scan.
