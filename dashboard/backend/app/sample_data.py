"""
Seeds clearly labelled [DEMO / SAMPLE DATA] for the DNSentinel Dashboard.
Populates SQLite with realistic DNS queries, cybersecurity threats, and client devices.
"""

import json
from datetime import datetime, timedelta, timezone
from app.database import get_db_connection


def seed_sample_data(force: bool = False):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if data already exists
    cursor.execute("SELECT COUNT(*) FROM queries")
    count = cursor.fetchone()[0]
    if count > 0 and not force:
        conn.close()
        return

    # Clear existing if force
    if force:
        cursor.execute("DELETE FROM queries")
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM clients")
        cursor.execute("DELETE FROM demo_settings")

    now = datetime.now(timezone.utc)

    # 1. Seed Client Devices
    clients_data = [
        ("192.168.1.10", "SOC-Analyst-PC", "Desktop", "Online", 342, 14, "Low", (now - timedelta(minutes=2)).isoformat()),
        ("192.168.1.25", "Finance-MacBook", "Laptop", "Online", 218, 5, "Low", (now - timedelta(minutes=5)).isoformat()),
        ("192.168.1.42", "Lab-Infected-Host", "Laptop", "Online", 412, 187, "High", (now - timedelta(seconds=12)).isoformat()),
        ("192.168.1.77", "IoT-SmartCamera-01", "IoT Gateway", "Online", 189, 44, "Medium", (now - timedelta(minutes=1)).isoformat()),
        ("192.168.1.105", "Developer-Linux-Box", "Desktop", "Online", 520, 18, "Low", (now - timedelta(minutes=8)).isoformat()),
        ("192.168.1.200", "Guest-Mobile-Phone", "Mobile", "Offline", 86, 22, "Medium", (now - timedelta(hours=3)).isoformat()),
    ]
    cursor.executemany(
        "INSERT INTO clients (ip, hostname, device_type, status, total_queries, blocked_queries, risk_level, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        clients_data
    )

    # 2. Seed Security Alerts (Realistic DNS threats with clear explanations)
    alerts_data = [
        (
            (now - timedelta(minutes=12)).isoformat(),
            "x892a7f8b91c01e.biz",
            "192.168.1.42",
            "DGA Malware Domain",
            "Critical",
            0.96,
            "High-probability Algorithmically Generated Domain (DGA) associated with active botnet C2 communication.",
            json.dumps([
                "Shannon character entropy is 4.41 bits/char (significantly above English baseline 2.8).",
                "Consonant-to-vowel ratio exceeds 8:1 with zero recognized language n-grams.",
                "Fast-path ML random forest tree classifier assigned confidence score of 96.4%.",
                "Domain registered 4 hours ago with privacy-masked registrar."
            ]),
            "Active",
            "Blocked"
        ),
        (
            (now - timedelta(minutes=28)).isoformat(),
            "exfil.f48e9a0.data-sync-srv.net",
            "192.168.1.42",
            "DNS Data Exfiltration Tunnel",
            "Critical",
            0.93,
            "Suspected covert data exfiltration tunnel abusing DNS TXT queries to bypass network boundary firewalls.",
            json.dumps([
                "High-frequency burst of 380 unique subdomains queried within a 60-second window.",
                "Subdomain payload contains Base32-encoded binary chunks averaging 58 bytes.",
                "Abnormal TXT record query volume (94% of client requests to this domain).",
                "Behavioral signature matches iodine/dnscat2 covert DNS tunnel tooling."
            ]),
            "Active",
            "Blocked"
        ),
        (
            (now - timedelta(minutes=45)).isoformat(),
            "metrics.shopper-offers.com",
            "192.168.1.25",
            "CNAME Cloaking Tracker",
            "Medium",
            0.79,
            "First-party subdomain cloaking a blacklisted third-party tracking and telemetry endpoint.",
            json.dumps([
                "Initial query for 'metrics.shopper-offers.com' resolved to CNAME 'tag.ad-target-telemetry.net'.",
                "Target canonical domain is flagged in the Disconnect & EasyPrivacy tracking blocklists.",
                "CNAME-cloaking defense intercepted recursive chase and returned 0.0.0.0."
            ]),
            "Mitigated",
            "Blocked"
        ),
        (
            (now - timedelta(hours=1, minutes=15)).isoformat(),
            "device-mgmt.local-setup-verify.com",
            "192.168.1.77",
            "DNS Rebinding Attack",
            "High",
            0.88,
            "Public internet domain attempting to resolve to private internal IPv4 subnet space to attack local devices.",
            json.dumps([
                "Public query response contained private RFC1918 address (192.168.1.1 router gateway).",
                "Record set with 0-second TTL to defeat browser Same-Origin Policy pin.",
                "DNSentinel Rebinding Shield blocked response from reaching internal client."
            ]),
            "Mitigated",
            "Blocked"
        ),
        (
            (now - timedelta(hours=2, minutes=10)).isoformat(),
            "secure-auth-update.bank-portal.com",
            "192.168.1.10",
            "Off-Path Cache Poisoning Attempt",
            "High",
            0.91,
            "Spoofed UDP response packet detected attempting to poison the recursive resolver cache.",
            json.dumps([
                "Transaction ID matched query, but UDP source port did not match randomized socket port.",
                "0x20 case-sensitive encoding mismatch: sent 'sEcUrE-aUtH', received 'secure-auth'.",
                "Forged packet dropped immediately; legit authoritative nameserver response was accepted."
            ]),
            "Mitigated",
            "Blocked"
        ),
        (
            (now - timedelta(hours=3, minutes=30)).isoformat(),
            "probe-random-nx.telemetry-node.org",
            "192.168.1.42",
            "NXDOMAIN Storm Anomaly",
            "Medium",
            0.76,
            "Client generated abnormal volume of non-existent domain queries indicating malware host discovery.",
            json.dumps([
                "142 consecutive NXDOMAIN responses recorded within 90 seconds.",
                "Queried domains follow sequential pseudo-random prefixes.",
                "Slow-path analyzer triggered client rate-limiting rule to mitigate resolver load."
            ]),
            "Active",
            "Rate-Limited"
        )
    ]
    cursor.executemany(
        "INSERT INTO alerts (timestamp, domain, client_ip, threat_type, severity, risk_score, description, detection_evidence, status, action_taken) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        alerts_data
    )

    # 3. Seed Realistic DNS Queries
    # Combination of benign lookups and blocked malicious/ad queries
    queries_seed = [
        # Normal queries
        ("github.com", "A", "NOERROR", 2, "HIT", 0.32, "ALLOW", None, "DoH", "192.168.1.10", "SOC-Analyst-PC", 1),
        ("api.github.com", "A", "NOERROR", 4, "HIT", 0.45, "ALLOW", None, "DoH", "192.168.1.10", "SOC-Analyst-PC", 2),
        ("raw.githubusercontent.com", "A", "NOERROR", 4, "MISS", 14.8, "ALLOW", None, "DoH", "192.168.1.10", "SOC-Analyst-PC", 3),
        ("en.wikipedia.org", "A", "NOERROR", 1, "HIT", 0.28, "ALLOW", None, "UDP", "192.168.1.25", "Finance-MacBook", 4),
        ("upload.wikimedia.org", "A", "NOERROR", 2, "HIT", 0.51, "ALLOW", None, "UDP", "192.168.1.25", "Finance-MacBook", 5),
        ("slack.com", "A", "NOERROR", 3, "HIT", 0.40, "ALLOW", None, "DoH", "192.168.1.25", "Finance-MacBook", 6),
        ("cdn.slack-edge.com", "A", "NOERROR", 4, "MISS", 12.4, "ALLOW", None, "DoH", "192.168.1.25", "Finance-MacBook", 7),
        ("fonts.googleapis.com", "A", "NOERROR", 1, "HIT", 0.18, "ALLOW", None, "DoT", "192.168.1.105", "Developer-Linux-Box", 8),
        ("fonts.gstatic.com", "A", "NOERROR", 2, "HIT", 0.22, "ALLOW", None, "DoT", "192.168.1.105", "Developer-Linux-Box", 9),
        ("registry.npmjs.org", "A", "NOERROR", 2, "MISS", 18.6, "ALLOW", None, "DoT", "192.168.1.105", "Developer-Linux-Box", 10),
        ("pypi.org", "A", "NOERROR", 4, "HIT", 0.65, "ALLOW", None, "DoT", "192.168.1.105", "Developer-Linux-Box", 11),
        ("cloudflare.com", "A", "NOERROR", 2, "HIT", 0.35, "ALLOW", None, "DoH", "192.168.1.10", "SOC-Analyst-PC", 12),
        ("dns.google", "A", "NOERROR", 2, "HIT", 0.25, "ALLOW", None, "UDP", "192.168.1.10", "SOC-Analyst-PC", 13),
        ("ntp.pool.org", "UDP", "NOERROR", 4, "MISS", 22.1, "ALLOW", None, "UDP", "192.168.1.77", "IoT-SmartCamera-01", 14),
        ("cam-cloud.surveillance-hub.net", "A", "NOERROR", 2, "MISS", 16.5, "ALLOW", None, "UDP", "192.168.1.77", "IoT-SmartCamera-01", 15),

        # Blocked queries (DGA, Adware, Tunnels, Rebinding)
        ("x892a7f8b91c01e.biz", "A", "NXDOMAIN", 0, "MISS", 1.2, "BLOCK", "DGA Malware Detected (Entropy: 4.41)", "UDP", "192.168.1.42", "Lab-Infected-Host", 16),
        ("v991k02zqa881b.biz", "A", "NXDOMAIN", 0, "MISS", 1.1, "BLOCK", "DGA Malware Detected (Score: 0.94)", "UDP", "192.168.1.42", "Lab-Infected-Host", 17),
        ("exfil.f48e9a0.data-sync-srv.net", "TXT", "NOERROR", 0, "MISS", 2.4, "BLOCK", "Covert DNS Tunnel Exfiltration (Burst: 380/min)", "UDP", "192.168.1.42", "Lab-Infected-Host", 18),
        ("chunk02.f48e9a0.data-sync-srv.net", "TXT", "NOERROR", 0, "MISS", 2.1, "BLOCK", "Covert DNS Tunnel Exfiltration", "UDP", "192.168.1.42", "Lab-Infected-Host", 19),
        ("doubleclick.net", "A", "NOERROR", 0, "HIT", 0.15, "BLOCK", "Blocklist: Ad Network (OISD / StevenBlack)", "DoH", "192.168.1.25", "Finance-MacBook", 20),
        ("pagead2.googlesyndication.com", "A", "NOERROR", 0, "HIT", 0.18, "BLOCK", "Blocklist: Ads & Trackers", "DoH", "192.168.1.25", "Finance-MacBook", 21),
        ("telemetry.ad-exchanger.net", "A", "NOERROR", 0, "HIT", 0.20, "BLOCK", "CNAME Cloaking: Target In Ad Blocklist", "DoH", "192.168.1.25", "Finance-MacBook", 22),
        ("device-mgmt.local-setup-verify.com", "A", "NOERROR", 0, "MISS", 1.8, "BLOCK", "DNS Rebinding Protection (Private IP 192.168.1.1 in public response)", "UDP", "192.168.1.77", "IoT-SmartCamera-01", 23),
        ("telemetry-beacon.tracking-cdn.xyz", "A", "NOERROR", 0, "HIT", 0.22, "BLOCK", "Blocklist: Telemetry & Spyware", "DoT", "192.168.1.77", "IoT-SmartCamera-01", 24),
        ("crypto-mining-pool.monero-node.cc", "A", "NOERROR", 0, "MISS", 1.5, "BLOCK", "Blocklist: Cryptojacking Node", "UDP", "192.168.1.42", "Lab-Infected-Host", 25),
        ("track.user-behavior-logger.info", "A", "NOERROR", 0, "HIT", 0.25, "BLOCK", "Blocklist: Analytics & Profiling", "DoH", "192.168.1.200", "Guest-Mobile-Phone", 26),
        ("popunder.ad-network-traffic.biz", "A", "NOERROR", 0, "HIT", 0.19, "BLOCK", "Blocklist: Aggressive Ad Popups", "UDP", "192.168.1.200", "Guest-Mobile-Phone", 27),
    ]

    # Expand the query set by generating staggered queries over the past 24 hours
    expanded_queries = []
    base_id = 1
    for minute_offset in range(120, -1, -2): # 60 timestamps over past 2 hours
        q_template = queries_seed[base_id % len(queries_seed)]
        q_time = (now - timedelta(minutes=minute_offset)).isoformat()
        expanded_queries.append((
            q_time,
            q_template[9],   # client_ip
            q_template[10],  # client_name
            q_template[0],   # qname
            q_template[1],   # qtype
            q_template[2],   # rcode
            q_template[3],   # answer_count
            q_template[4],   # cache_status
            round(q_template[5] + (base_id % 7) * 0.12, 2), # latency
            q_template[6],   # policy_action
            q_template[7],   # block_reason
            q_template[8],   # protocol
        ))
        base_id += 1

    cursor.executemany(
        """
        INSERT INTO queries (timestamp, client_ip, client_name, qname, qtype, rcode, answer_count, cache_status, latency_ms, policy_action, block_reason, protocol)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        expanded_queries
    )

    # 4. Seed Demo Settings
    settings_seed = [
        ("ml_dga_threshold", "0.75"),
        ("tunnel_entropy_threshold", "4.5"),
        ("rate_limit_rps", "100"),
        ("cache_ttl_seconds", "300"),
        ("enable_cname_inspection", "true"),
        ("enable_0x20_encoding", "true"),
        ("log_retention_days", "7"),
        ("demo_mode", "true")
    ]
    cursor.executemany(
        "INSERT OR REPLACE INTO demo_settings (key, value) VALUES (?, ?)",
        settings_seed
    )

    conn.commit()
    conn.close()
