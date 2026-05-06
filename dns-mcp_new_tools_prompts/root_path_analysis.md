# Claude Code Prompt: `root_path_analysis`

Add a new dns-mcp tool called `root_path_analysis` to the existing FastMCP server.

This tool combines a DNS timing probe with a traceroute to the same root server IP
and attempts to correlate them into a coherent path + performance picture.

Steps:
1. Resolve the target root letter to its canonical IPv4 (and optionally IPv6) address
   from the hardcoded IANA list.
2. Run a CHAOS TXT query (`hostname.bind`) with timing to get RTT and instance ID.
3. Execute a traceroute using Python's subprocess to call `traceroute` (Linux) with
   a reasonable max-hops (default 20) and a short per-hop timeout. Parse stdout into
   a list of hops: hop number, IP, hostname if resolved, RTT per probe.
4. For each hop IP, attempt an ASN lookup via dnspython's CHAOS or via the
   `<reversed-ip>.origin.asn.cymru.com` TXT query pattern. Return ASN and org name
   where resolvable.
5. Identify the likely "last-mile AS" (the AS just before the destination) and the
   "origin AS" (first non-RFC1918 hop).

Parameters:
- letter: str  # a-m
- ip_version: Literal["ipv4", "ipv6"] = "ipv4"
- max_hops: int = 20
- timeout: float = 5.0

Return: letter, root IP, CHAOS instance string, DNS RTT ms, hop count, full hop list
with ASN annotations, last-mile AS, origin AS, and a `path_summary` string suitable
for analyst consumption (e.g., "8 hops, 3 ASes, last-mile AS7922 Comcast, landed on
lax.f.root-servers.org, RTT 12.4ms").

Important: subprocess calls must be non-blocking with a hard wall-clock timeout.
If traceroute is not available in the container, catch the error and return partial
results (DNS RTT only) with a clear flag. Follow existing tool patterns for error
handling and Pydantic validation.
