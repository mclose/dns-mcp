# Claude Code Prompt: `root_anycast_coverage`

Add a new dns-mcp tool called `root_anycast_coverage` to the existing FastMCP server.

This tool characterizes the anycast deployment of a specific root server letter by
attempting to fingerprint reachable instances and summarizing known deployment data.

Two data sources:

1. CHAOS TXT probe: Query `hostname.bind` and `id.server` directly against the root
   letter's IP. Parse the instance identifier string — many operators encode PoP
   location (e.g., `lax.f.root-servers.org`, `korg-kads1.k.ripe.net`). Extract and
   return the raw string plus any parseable location hint.

2. Static coverage metadata: Embed a hardcoded dict of known anycast site counts per
   letter sourced from each operator's published data (approximate, with a note that
   these drift). Include: letter, operator, ASN(s), approximate site count, IPv6
   support, known anycast or effectively unicast (flag E, G, H appropriately).

Parameters:
- letter: str  # single letter a-m, case insensitive
- timeout: float = 3.0

Return: operator info, ASN list, known site count, IPv6 support flag, CHAOS instance
string from this vantage point, parsed PoP hint if extractable, and a `limited_anycast`
boolean that is True for E, G, H.

Add a note in the docstring: the CHAOS response reflects only the instance this
particular vantage point (the docker container's resolver path) reaches — it is a
single data point, not a full enumeration. Full enumeration requires a distributed
probe network like RIPE Atlas.

Follow existing FastMCP/Pydantic patterns in the codebase.
