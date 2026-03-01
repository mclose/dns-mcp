#!/usr/bin/env python3
"""
nsec3-explorer.py — Visual NSEC3 chain explorer for DNSSEC-signed zones.

Performs an AXFR (zone transfer) to discover all names in a zone, computes
their NSEC3 hashes, and maps the complete denial-of-existence chain. Then
sends a probe query for a nonexistent name and shows exactly how the NSEC3
records in the response prove it doesn't exist.

Requirements:
    pip install dnspython

Usage:
    python3 nsec3-explorer.py nsec3-weak.deflationhollow.net
    python3 nsec3-explorer.py example.com --ns ns1.example.com
    python3 nsec3-explorer.py example.com --probe test.example.com

Notes:
    - Requires AXFR access to the zone's nameserver (usually restricted)
    - Works with any NSEC3-signed zone you can transfer
    - Also handles plain NSEC zones (shows the cleartext chain instead)
"""

import argparse
import hashlib
import base64
import sys

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.flags
    import dns.resolver
    import dns.rcode
    import dns.zone
    import dns.name
except ImportError:
    print("Error: dnspython is required. Install with: pip install dnspython")
    sys.exit(1)


def dns_wire_format(name):
    """Convert a domain name to DNS wire format (lowercase, length-prefixed labels).

    Example: "mail.example.com." -> b'\\x04mail\\x07example\\x03com\\x00'
    """
    labels = name.lower().rstrip(".").split(".")
    result = b""
    for label in labels:
        result += bytes([len(label)]) + label.encode("ascii")
    result += b"\x00"
    return result


def nsec3_hash(name, algorithm=1, iterations=0, salt=b""):
    """Compute NSEC3 hash per RFC 5155 Section 5.

    IH(salt, x, 0) = H(x || salt)
    IH(salt, x, k) = H(IH(salt, x, k-1) || salt)

    Only algorithm 1 (SHA-1) is defined.
    """
    if algorithm != 1:
        raise ValueError(f"Unsupported NSEC3 algorithm: {algorithm} (only SHA-1/1 is defined)")
    wire = dns_wire_format(name)
    digest = hashlib.sha1(wire + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return digest


def base32hex_encode(data):
    """RFC 4648 Section 7 base32hex encoding (alphabet 0-9A-V), no padding.

    NSEC3 uses base32hex, NOT standard base32 (alphabet A-Z2-7).
    """
    std = base64.b32encode(data).decode("ascii").rstrip("=")
    table = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "0123456789ABCDEFGHIJKLMNOPQRSTUV",
    )
    return std.translate(table)


def resolve_ns(domain):
    """Resolve the first authoritative NS for a domain to an IP address."""
    resolver = dns.resolver.Resolver()
    ns_answers = resolver.resolve(domain, "NS")
    ns_hostname = str(ns_answers[0].target).rstrip(".")
    a_answers = resolver.resolve(ns_hostname, "A")
    ns_ip = str(a_answers[0])
    return ns_hostname, ns_ip


def do_axfr(domain, ns_ip):
    """Perform an AXFR and return all owner names and their record types."""
    z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10.0))
    names = {}
    zone_origin = z.origin.to_text().rstrip(".")
    for name, node in z.nodes.items():
        fqdn = name.derelativize(z.origin).to_text().rstrip(".")
        types = set()
        for rdataset in node.rdatasets:
            type_text = dns.rdatatype.to_text(rdataset.rdtype)
            types.add(type_text)
        names[fqdn] = sorted(types)
    return names


def get_nsec3param(domain, ns_ip):
    """Query NSEC3PARAM at the zone apex. Returns (algorithm, iterations, salt) or None."""
    query = dns.message.make_query(domain, dns.rdatatype.NSEC3PARAM, want_dnssec=True)
    query.flags |= dns.flags.CD
    response = dns.query.udp(query, ns_ip, timeout=5.0)
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.NSEC3PARAM:
            rdata = list(rrset)[0]
            return {
                "algorithm": rdata.algorithm,
                "iterations": rdata.iterations,
                "salt": rdata.salt if rdata.salt else b"",
                "salt_hex": rdata.salt.hex() if rdata.salt else "(none)",
                "flags": rdata.flags,
            }
    return None


def probe_nxdomain(domain, ns_ip, probe_name=None):
    """Send a DNSSEC probe query for a nonexistent name. Returns the response."""
    if probe_name is None:
        probe_name = f"_nsec3-probe.{domain}"
    query = dns.message.make_query(probe_name, "A", want_dnssec=True)
    query.flags |= dns.flags.CD
    query.flags &= ~dns.flags.RD
    return dns.query.udp(query, ns_ip, timeout=5.0), probe_name


def extract_nsec3_from_response(response):
    """Extract NSEC3 records from a response's authority section."""
    records = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC3:
            for rdata in rrset:
                owner_hash = str(rrset.name).split(".")[0].upper()
                next_hash = base32hex_encode(rdata.next).upper()
                # Extract type bitmap
                types = []
                for window_num, bitmap in rdata.windows:
                    for byte_idx, byte_val in enumerate(bitmap):
                        for bit in range(8):
                            if byte_val & (0x80 >> bit):
                                rdtype_num = window_num * 256 + byte_idx * 8 + bit
                                try:
                                    types.append(dns.rdatatype.to_text(rdtype_num))
                                except Exception:
                                    types.append(f"TYPE{rdtype_num}")
                records.append({
                    "owner_hash": owner_hash,
                    "next_hash": next_hash,
                    "types": types,
                    "algorithm": rdata.algorithm,
                    "iterations": rdata.iterations,
                    "salt": rdata.salt.hex() if rdata.salt else "",
                })
    return records


def extract_nsec_from_response(response):
    """Extract plain NSEC records from a response's authority section."""
    records = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            for rdata in rrset:
                records.append({
                    "owner": str(rrset.name).rstrip("."),
                    "next_name": str(rdata.next).rstrip("."),
                    "text": str(rdata),
                })
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Visual NSEC3 chain explorer for DNSSEC-signed zones.",
        epilog="Requires AXFR access to the target zone's nameserver.",
    )
    parser.add_argument("domain", help="Zone to explore (e.g., nsec3-weak.deflationhollow.net)")
    parser.add_argument("--ns", help="Nameserver to query (default: auto-resolve from NS records)")
    parser.add_argument("--probe", help="Specific name to probe (default: _nsec3-probe.<domain>)")
    args = parser.parse_args()

    domain = args.domain.rstrip(".")

    # --- Step 1: Resolve nameserver ---
    print(f"Zone: {domain}")
    print()

    if args.ns:
        ns_hostname = args.ns
        resolver = dns.resolver.Resolver()
        ns_ip = str(resolver.resolve(ns_hostname, "A")[0])
    else:
        ns_hostname, ns_ip = resolve_ns(domain)

    print(f"Nameserver: {ns_hostname} ({ns_ip})")
    print()

    # --- Step 2: Check NSEC3PARAM ---
    params = get_nsec3param(domain, ns_ip)

    if params:
        print(f"NSEC3PARAM: algorithm={params['algorithm']} (SHA-1) "
              f"iterations={params['iterations']} salt={params['salt_hex']}")
        print()
    else:
        # Might be plain NSEC — continue and the probe will tell us
        print("NSEC3PARAM: not found (zone may use plain NSEC)")
        print()

    # --- Step 3: AXFR ---
    print("Performing zone transfer (AXFR)...")
    try:
        zone_names = do_axfr(domain, ns_ip)
    except Exception as e:
        print(f"AXFR failed: {e}")
        print("Zone transfer access is required. Check ACLs on the nameserver.")
        sys.exit(1)

    # Filter out NSEC3 hash owner names (they show up in the AXFR too)
    real_names = {}
    for name, types in zone_names.items():
        label = name.split(".")[0]
        # NSEC3 hash labels are exactly 32 chars of base32hex (0-9A-V)
        if len(label) == 32 and all(c in "0123456789ABCDEFGHIJKLMNOPQRSTUVabcdefghijklmnopqrstuv" for c in label):
            continue
        real_names[name] = types

    print(f"Found {len(real_names)} names in zone:")
    print()
    max_name_len = max(len(n) for n in real_names)
    for name in sorted(real_names):
        types_str = " ".join(real_names[name])
        print(f"  {name:<{max_name_len}}  {types_str}")
    print()

    # --- Step 4: Probe for NXDOMAIN ---
    print("-" * 70)
    response, probe_name = probe_nxdomain(domain, ns_ip, args.probe)
    rcode = dns.rcode.to_text(response.rcode())
    print(f"Probe: {probe_name} -> {rcode}")
    print()

    # Check for NSEC3 vs NSEC
    nsec3_records = extract_nsec3_from_response(response)
    nsec_records = extract_nsec_from_response(response)

    if nsec3_records:
        show_nsec3_analysis(domain, params, real_names, nsec3_records, probe_name)
    elif nsec_records:
        show_nsec_analysis(domain, real_names, nsec_records, probe_name)
    else:
        print("No NSEC or NSEC3 records in the authority section.")
        print("The zone may not be DNSSEC-signed.")


def show_nsec3_analysis(domain, params, real_names, nsec3_records, probe_name):
    """Display the full NSEC3 chain analysis."""
    algorithm = params["algorithm"] if params else 1
    iterations = params["iterations"] if params else 0
    salt = params["salt"] if params else b""

    # --- Compute hashes for all real names ---
    print("NSEC3 HASH COMPUTATION")
    print("=" * 70)
    print()
    print(f"  H(name) = SHA-1( wire_format(lowercase(name)) || salt )")
    if iterations > 0:
        print(f"  Iterated {iterations} additional time(s)")
    if salt:
        print(f"  Salt: {salt.hex()} ({len(salt)} bytes)")
    else:
        print(f"  Salt: (none)")
    print()

    hash_to_name = {}
    entries = []
    max_name_len = max(len(n) for n in real_names)

    for name in sorted(real_names):
        h = base32hex_encode(nsec3_hash(name, algorithm, iterations, salt))
        hash_to_name[h] = name
        entries.append((h, name))
        print(f"  {name:<{max_name_len}}  ->  {h}")

    # Also hash the probe name
    probe_hash = base32hex_encode(nsec3_hash(probe_name, algorithm, iterations, salt))
    print()
    print(f"  {probe_name:<{max_name_len}}  ->  {probe_hash}  (probe)")
    print()

    # --- Show the sorted circular chain ---
    entries.sort(key=lambda x: x[0])

    print("NSEC3 CHAIN (sorted by hash)")
    print("=" * 70)
    print()

    for i, (h, name) in enumerate(entries):
        next_h, next_name = entries[(i + 1) % len(entries)]
        short = name.split(".")[0] if name != domain else "(apex)"

        # Determine what types are at this hash from the AXFR
        types_str = " ".join(real_names.get(name, ["?"]))

        print(f"  {h}  = {short}")
        print(f"    Types: {types_str}")
        print(f"    Next:  {next_h}")
        if i < len(entries) - 1:
            print(f"    \"Nothing exists between me and the next hash.\"")
        else:
            print(f"    \"Nothing exists between me and the first hash (wrap-around).\"")
        print()

    # --- Show where the probe falls ---
    print("DENIAL-OF-EXISTENCE PROOF")
    print("=" * 70)
    print()
    print(f"  Probe name: {probe_name}")
    print(f"  Probe hash: {probe_hash}")
    print()

    # Find the covering NSEC3 record (from the actual response)
    for rec in nsec3_records:
        owner = rec["owner_hash"]
        next_h = rec["next_hash"]
        owner_name = hash_to_name.get(owner, "?")
        next_name = hash_to_name.get(next_h, "?")

        owner_short = owner_name.split(".")[0] if owner_name != domain else "(apex)"
        next_short = next_name.split(".")[0] if next_name != domain else "(apex)"

        # Check if this record covers the probe hash
        if owner < next_h:
            covers = owner < probe_hash < next_h
        else:
            # Wrap-around case
            covers = probe_hash > owner or probe_hash < next_h

        if covers:
            marker = "  ** COVERS PROBE **"
        else:
            marker = ""

        types_str = " ".join(rec["types"])
        print(f"  NSEC3 from response:")
        print(f"    {owner} ({owner_short})")
        print(f"      -> {next_h} ({next_short})")
        print(f"    Types at owner: {types_str}")
        if covers:
            print(f"    PROVES: {probe_hash} falls in this gap -> name does not exist")
        print()

    # --- Summary ---
    print("SECURITY OBSERVATIONS")
    print("=" * 70)
    print()
    print(f"  Zone has {len(entries)} names")
    print(f"  Hash chain reveals: {len(entries)} names exist (but not what they're called)")
    print(f"  Type bitmaps reveal: record types at each hashed name")
    if not salt and iterations == 0:
        print(f"  Risk: Single-pass SHA-1 with no salt — precomputed dictionary attack is trivial")
        print(f"         (RFC 9276 accepts this trade-off for resolver performance)")
    elif iterations == 0:
        print(f"  Risk: Single-pass SHA-1 with {len(salt)}-byte salt — rainbow tables defeated")
        print(f"         but per-zone dictionary attack still feasible")
    else:
        print(f"  Risk: {iterations} iterations with salt — slower to brute-force")
        print(f"         but GPU attacks still practical for common hostnames")
    print()


def show_nsec_analysis(domain, real_names, nsec_records, probe_name):
    """Display plain NSEC chain analysis — names are in cleartext."""
    print("NSEC CHAIN (plaintext — zone is fully walkable)")
    print("=" * 70)
    print()
    print("  Plain NSEC exposes every name in the zone directly.")
    print("  No hashing — an attacker follows the chain to enumerate all names.")
    print()

    for rec in nsec_records:
        print(f"  {rec['owner']}  ->  {rec['next_name']}")
        print(f"    \"The next name after me is {rec['next_name']}\"")
        print()

    print("  All names from AXFR (for comparison):")
    for name in sorted(real_names):
        types_str = " ".join(real_names[name])
        print(f"    {name}  ({types_str})")
    print()

    print("SECURITY OBSERVATIONS")
    print("=" * 70)
    print()
    print(f"  Zone has {len(real_names)} names — ALL exposed in cleartext via NSEC chain")
    print(f"  No AXFR needed: just follow NSEC records from the apex to enumerate everything")
    print(f"  This is the primary reason NSEC3 was created (RFC 5155)")
    print()


if __name__ == "__main__":
    main()
