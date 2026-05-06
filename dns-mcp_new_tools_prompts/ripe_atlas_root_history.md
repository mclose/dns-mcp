# Claude Code Prompt: `ripe_atlas_root_history`

Add a new dns-mcp tool called `ripe_atlas_root_history` to the existing FastMCP server.

This tool queries the RIPE Atlas REST API for a specific built-in root server
measurement and summarizes historical RTT data.

RIPE Atlas runs continuous built-in measurements to all root letters. Known stable
measurement IDs should be embedded as a reference dict (e.g.,
{1: "a-root", 2: "b-root", ...} — look these up from
https://atlas.ripe.net/measurements/ or embed the known IDs for root letter queries).

Steps:
1. Accept either a measurement ID directly or a root letter (a-m) and resolve to
   the corresponding built-in measurement ID from the embedded dict.
2. Call the RIPE Atlas results API:
   `https://atlas.ripe.net/api/v2/measurements/{msm_id}/results/`
   with parameters: start (unix timestamp), stop, limit (default 500).
3. Parse result objects: each contains `avg`, `min`, `max` RTT fields and `prb_id`
   (probe ID). Optionally include `fw` (firmware) and `from` (probe IP) if present.
4. Compute summary statistics: mean RTT, p50, p95, p99, min, max, sample count,
   percentage of timeouts/failures.
5. Optionally group by time bucket (hourly or daily) for trend output.

Parameters:
- measurement_id: Optional[int] = None
- letter: Optional[str] = None  # a-m; one of measurement_id or letter required
- hours_back: int = 24  # how far back to pull data
- bucket: Literal["none", "hourly", "daily"] = "none"
- max_results: int = 500

Use httpx or urllib (no requests — check what's already in the project deps) for the
API call. The RIPE Atlas API is public and requires no auth for built-in measurements
at reasonable query rates.

Return: measurement ID, letter, time range, sample count, RTT stats (mean/p50/p95/p99/
min/max), failure rate, and bucketed series if requested.

Add a note in the docstring: RIPE Atlas probe distribution is Europe-heavy; RTT
statistics will be skewed accordingly. Raw percentiles reflect the probe population,
not global user experience.

Follow existing FastMCP/Pydantic patterns. Validate that at least one of measurement_id
or letter is provided.
