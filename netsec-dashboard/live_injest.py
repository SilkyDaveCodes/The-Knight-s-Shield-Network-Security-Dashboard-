import subprocess, json, os, snowflake.connector, ipaddress, re, requests
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

conn = snowflake.connector.connect(
    user=os.getenv("SNOW_USER"),
    password=os.getenv("SNOW_PASSWORD"),
    account=os.getenv("SNOW_ACCOUNT"),
    warehouse=os.getenv("SNOW_WAREHOUSE"),
    database=os.getenv("SNOW_DATABASE"),
    schema=os.getenv("SNOW_SCHEMA")
)
cur = conn.cursor()


def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except:
        return False


def get_country(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        data = r.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"


def score_packet(proto, src, dst, dst_port, length, payload_text=None):
    score = 0.0
    reasons = []

    bad_protocols = ["ftp", "smtp", "tftp", "http"]
    for p in bad_protocols:
        if p in proto:
            score += 0.3
            reasons.append(f"Uses insecure protocol {p.upper()}")

    if src and dst and is_public_ip(dst) and not is_public_ip(src):
        score += 0.3
        reasons.append("Outbound connection to public IP")

    if payload_text:
        if re.search(r"(user|pass|login|token|key|auth)", payload_text, re.IGNORECASE):
            score += 0.4
            reasons.append("Possible credentials in payload")

    country = get_country(dst)
    risky_countries = ["RU", "CN", "KP", "IR"]
    if country in risky_countries:
        score += 0.3
        reasons.append(f"Destination in {country}")

    if length > 1000:
        score += 0.2
        reasons.append("Unusually large packet size")

    return round(min(score, 1.0), 2), ", ".join(reasons) if reasons else "Normal traffic"


cmd = ["tshark", "-i", "en0", "-T", "ek"]
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

print("Capturing packets on en0 and analyzing...")

for line in proc.stdout:
    line = line.strip()
    if not line or line.startswith("{\"index\""):  
        continue

    try:
        pkt = json.loads(line)

        layers = pkt.get("layers", {})
        if not layers:
            layers = pkt.get("_source", {}).get("layers", {})

        ip = layers.get("ip", {})
        frame = layers.get("frame", {})
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})

        src = ip.get("ip_ip_src") or ip.get("ip.src")
        dst = ip.get("ip_ip_dst") or ip.get("ip.dst")
        proto = frame.get("frame_frame_protocols") or frame.get("frame.protocols") or "unknown"
        length = int(frame.get("frame_frame_len") or frame.get("frame.len") or 0)

        dst_port = tcp.get("tcp_tcp_dstport") or tcp.get("tcp.dstport") or \
                   udp.get("udp_udp_dstport") or udp.get("udp.dstport")
        dst_port = int(dst_port) if dst_port else None

        payload_text = None
        data_field = layers.get("data", {})
        if isinstance(data_field, dict):
            payload_text = str(data_field.get("data_data") or data_field.get("data.data") or "")

        if src and dst:
            score, reason = score_packet(proto, src, dst, dst_port, length, payload_text)

            print(f"📦 SRC={src} → DST={dst} PORT={dst_port} PROTO={proto} LEN={length} → SCORE={score} ({reason})")

            cur.execute("""
                INSERT INTO PACKETS (TS, SRC, DST, DST_PORT, PROTO, LEN, SUSPICIOUS_SCORE, REASON)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                datetime.now(timezone.utc),
                src,
                dst,
                dst_port,
                proto,
                length,
                score,
                reason
            ))
            conn.commit()

    except json.JSONDecodeError:
        continue
    except Exception as e:
        print("⚠️ Error inserting:", e)
