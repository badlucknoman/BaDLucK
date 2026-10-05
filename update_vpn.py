import requests
import base64
import json
import sys
import re
import os


# ============================================================
# API ENDPOINTS
# ============================================================

VPNGATE_CSV_URL = "http://www.vpngate.net/api/iphone/"

TELEXY_TCP_URL = (
    "https://telexy.net/api/v1/vpn"
    "?transport=tcp&sort=ping&limit=300"
)

TELEXY_UDP_URL = (
    "https://telexy.net/api/v1/vpn"
    "?transport=udp&sort=ping&limit=300"
)


# ============================================================
# HTTP HEADERS
# ============================================================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 "
        "(Linux; Android 15) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/140.0 Mobile Safari/537.36"
    ),
    "Accept": "*/*"
}


# ============================================================
# REQUEST SETTINGS
# ============================================================

REQUEST_TIMEOUT = 30


# ============================================================
# BASE64 ENCODING
# ============================================================

def encode_ovpn_config(config):

    if not config:
        return ""

    try:

        config = str(config).strip()

        if not config:
            return ""

        return base64.b64encode(
            config.encode("utf-8")
        ).decode("ascii")

    except Exception as e:

        print(f"Base64 encoding error: {e}")

        return ""


# ============================================================
# NORMALIZE PROTOCOL
# ============================================================

def normalize_protocol(protocol):

    if not protocol:
        return ""

    protocol = str(protocol).lower().strip()

    if "tcp" in protocol:
        return "tcp"

    if "udp" in protocol:
        return "udp"

    return ""


# ============================================================
# DETECT PROTOCOL FROM OVPN
# ============================================================

def detect_protocol_from_ovpn(config):

    if not config:
        return ""

    try:

        text = str(config).lower()

        if re.search(
            r"^\s*proto\s+tcp",
            text,
            re.MULTILINE
        ):
            return "tcp"

        if re.search(
            r"^\s*proto\s+udp",
            text,
            re.MULTILINE
        ):
            return "udp"

    except Exception:
        pass

    return ""


# ============================================================
# EXTRACT REMOTE
# ============================================================

def extract_remote(config):

    if not config:
        return "", ""

    try:

        match = re.search(
            r"^\s*remote\s+([^\s]+)\s+([0-9]+)",
            config,
            re.MULTILINE | re.IGNORECASE
        )

        if match:

            return (
                match.group(1).strip(),
                match.group(2).strip()
            )

    except Exception:
        pass

    return "", ""


# ============================================================
# CLEAN OVPN CONFIG
# ============================================================

def clean_ovpn_config(config):

    if not config:
        return ""

    try:

        lines = config.splitlines()
        cleaned = []

        for line in lines:

            stripped = line.strip()

            # Remove data-ciphers AES-128-CBC.
            if stripped.lower().startswith("data-ciphers "):

                if "AES-128-CBC" in stripped.upper():
                    continue

            cleaned.append(line)

        return "\n".join(cleaned).strip()

    except Exception:

        return config


# ============================================================
# UNIQUE SERVER KEY
# ============================================================

def make_unique_key(ip, protocol):

    return (
        str(ip).strip().lower()
        + "|"
        + str(protocol).strip().lower()
    )


# ============================================================
# FETCH VPNGATE
# ============================================================

def fetch_vpngate_csv(existing_keys):

    configs = []

    try:

        print("Fetching VPN Gate servers...")

        response = requests.get(
            VPNGATE_CSV_URL,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT
        )

        print(
            f"VPN Gate HTTP status: {response.status_code}"
        )

        if response.status_code != 200:

            print("VPN Gate request failed.")

            return configs

        lines = response.text.splitlines()

        for line in lines:

            try:

                if (
                    line.startswith("#")
                    or line.startswith("*")
                    or not line.strip()
                ):
                    continue

                parts = line.split(",")

                if len(parts) < 15:
                    continue

                ip = parts[1].strip()
                score = parts[2].strip()
                ping = parts[3].strip()
                speed = parts[4].strip()
                country = parts[5].strip()
                country_code = parts[6].strip()
                base64_config = parts[14].strip()

                if not ip or not base64_config:
                    continue

                try:

                    ovpn_config = base64.b64decode(
                        base64_config,
                        validate=False
                    ).decode(
                        "utf-8",
                        errors="ignore"
                    )

                except Exception:

                    continue

                if not ovpn_config.strip():
                    continue

                ovpn_config = clean_ovpn_config(
                    ovpn_config
                )

                protocol = detect_protocol_from_ovpn(
                    ovpn_config
                )

                if not protocol:
                    continue

                unique_key = make_unique_key(
                    ip,
                    protocol
                )

                if unique_key in existing_keys:
                    continue

                remote_host, remote_port = extract_remote(
                    ovpn_config
                )

                encoded_config = encode_ovpn_config(
                    ovpn_config
                )

                if not encoded_config:
                    continue

                server = {
                    "ip": ip,
                    "port": remote_port,
                    "country": country,
                    "country_code": country_code.upper(),
                    "protocol": protocol,
                    "ping": ping,
                    "speed": speed,
                    "score": score,
                    "source": "vpngate",
                    "ovpn_config": encoded_config
                }

                configs.append(server)

                existing_keys.add(unique_key)

            except Exception:

                continue

    except Exception as e:

        print(f"VPN Gate error: {e}")

    print(
        f"VPN Gate servers collected: {len(configs)}"
    )

    return configs


# ============================================================
# FETCH TELEXy
# ============================================================

def fetch_telexy_json(
    url,
    default_protocol,
    existing_keys
):

    configs = []

    try:

        print(
            f"Fetching Telexy "
            f"{default_protocol.upper()} servers..."
        )

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT
        )

        print(
            f"Telexy HTTP status: {response.status_code}"
        )

        if response.status_code != 200:

            print(
                f"Telexy {default_protocol.upper()} "
                f"request failed."
            )

            return configs

        data = response.json()

        if isinstance(data, list):

            items = data

        elif isinstance(data, dict):

            items = (
                data.get("data")
                or data.get("results")
                or data.get("servers")
                or []
            )

        else:

            items = []

        if not isinstance(items, list):
            return configs

        for item in items:

            try:

                if not isinstance(item, dict):
                    continue

                # ==================================================
                # IP
                # ==================================================

                ip = str(
                    item.get("ip")
                    or item.get("ip_address")
                    or item.get("host")
                    or ""
                ).strip()

                if not ip:
                    continue

                # ==================================================
                # PROTOCOL
                # ==================================================

                protocol = normalize_protocol(
                    item.get("transport")
                    or item.get("protocol")
                    or default_protocol
                )

                if not protocol:

                    protocol = default_protocol

                # ==================================================
                # OVPN CONFIG
                # ==================================================

                raw_config = (
                    item.get("ovpn_config")
                    or item.get("config")
                    or item.get("ovpn")
                    or item.get("openvpn")
                    or ""
                )

                if not raw_config:
                    continue

                raw_config = str(
                    raw_config
                ).strip()

                # ==================================================
                # CHECK BASE64
                # ==================================================

                is_base64 = False

                try:

                    test_base64 = re.sub(
                        r"\s+",
                        "",
                        raw_config
                    )

                    decoded = base64.b64decode(
                        test_base64,
                        validate=True
                    )

                    decoded_text = decoded.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    if (
                        "client" in decoded_text.lower()
                        or "remote " in decoded_text.lower()
                        or "proto " in decoded_text.lower()
                        or "<ca>" in decoded_text.lower()
                    ):

                        is_base64 = True

                except Exception:

                    is_base64 = False

                # ==================================================
                # BASE64 CONFIG
                # ==================================================

                if is_base64:

                    encoded_config = re.sub(
                        r"\s+",
                        "",
                        raw_config
                    )

                    try:

                        decoded_config = base64.b64decode(
                            encoded_config
                        ).decode(
                            "utf-8",
                            errors="ignore"
                        )

                        detected_protocol = (
                            detect_protocol_from_ovpn(
                                decoded_config
                            )
                        )

                        if detected_protocol:

                            protocol = detected_protocol

                    except Exception:

                        pass

                # ==================================================
                # PLAIN TEXT CONFIG
                # ==================================================

                else:

                    clean_config = clean_ovpn_config(
                        raw_config
                    )

                    detected_protocol = (
                        detect_protocol_from_ovpn(
                            clean_config
                        )
                    )

                    if detected_protocol:

                        protocol = detected_protocol

                    encoded_config = encode_ovpn_config(
                        clean_config
                    )

                if not encoded_config:
                    continue

                # ==================================================
                # UNIQUE KEY
                # ==================================================

                unique_key = make_unique_key(
                    ip,
                    protocol
                )

                if unique_key in existing_keys:
                    continue

                # ==================================================
                # SERVER INFO
                # ==================================================

                country = str(
                    item.get("country")
                    or item.get("country_name")
                    or "Unknown"
                ).strip()

                country_code = str(
                    item.get("country_code")
                    or item.get("country_short")
                    or "XX"
                ).strip().upper()

                ping = str(
                    item.get("ping")
                    or item.get("latency")
                    or 0
                ).strip()

                speed = str(
                    item.get("speed")
                    or item.get("download_speed")
                    or 0
                ).strip()

                score = str(
                    item.get("score")
                    or 0
                ).strip()

                port = str(
                    item.get("port")
                    or item.get("server_port")
                    or ""
                ).strip()

                server = {
                    "ip": ip,
                    "port": port,
                    "country": country,
                    "country_code": country_code,
                    "protocol": protocol,
                    "ping": ping,
                    "speed": speed,
                    "score": score,
                    "source": "telexy",
                    "ovpn_config": encoded_config
                }

                configs.append(server)

                existing_keys.add(unique_key)

            except Exception:

                continue

    except Exception as e:

        print(
            f"Telexy {default_protocol.upper()} "
            f"error: {e}"
        )

    print(
        f"Telexy {default_protocol.upper()} "
        f"servers collected: {len(configs)}"
    )

    return configs


# ============================================================
# NUMERIC VALUE
# ============================================================

def numeric_value(value):

    try:

        if value is None:
            return 0

        text = str(value)

        match = re.search(
            r"[-+]?[0-9]*\.?[0-9]+",
            text
        )

        if match:

            return float(
                match.group(0)
            )

    except Exception:

        pass

    return 0


# ============================================================
# WRITE JSON SAFELY
# ============================================================

def write_json(filename, data):

    if not isinstance(data, list):

        raise ValueError(
            f"{filename}: data is not a list"
        )

    if len(data) == 0:

        raise ValueError(
            f"{filename}: refusing to write empty JSON"
        )

    temp_file = filename + ".tmp"

    with open(
        temp_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False
        )

        file.write("\n")

    # Replace only after successful write.
    os.replace(
        temp_file,
        filename
    )

    print(
        f"Written {filename}: {len(data)} servers"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 60)
    print("VPN SERVER UPDATE STARTED")
    print("=" * 60)
    print()

    all_configs = []

    seen_keys = set()

    # ========================================================
    # VPN GATE
    # ========================================================

    vpngate_servers = fetch_vpngate_csv(
        seen_keys
    )

    all_configs.extend(
        vpngate_servers
    )

    # ========================================================
    # TELEXy TCP
    # ========================================================

    telexy_tcp_servers = fetch_telexy_json(
        TELEXY_TCP_URL,
        "tcp",
        seen_keys
    )

    all_configs.extend(
        telexy_tcp_servers
    )

    # ========================================================
    # TELEXy UDP
    # ========================================================

    telexy_udp_servers = fetch_telexy_json(
        TELEXY_UDP_URL,
        "udp",
        seen_keys
    )

    all_configs.extend(
        telexy_udp_servers
    )

    # ========================================================
    # CHECK TOTAL RESULT
    # ========================================================

    if not all_configs:

        print()
        print("ERROR: No VPN configurations collected.")
        print("Existing JSON files will NOT be overwritten.")
        print()

        sys.exit(1)

    # ========================================================
    # NORMALIZE PROTOCOL
    # ========================================================

    for server in all_configs:

        server["protocol"] = normalize_protocol(
            server.get("protocol")
        )

    # Remove invalid protocol entries.

    all_configs = [
        server
        for server in all_configs
        if server.get("protocol") in ("tcp", "udp")
    ]

    if not all_configs:

        print(
            "ERROR: No valid TCP/UDP servers found."
        )

        sys.exit(1)

    # ========================================================
    # SEPARATE TCP / UDP
    # ========================================================

    tcp_servers = [
        server
        for server in all_configs
        if server.get("protocol") == "tcp"
    ]

    udp_servers = [
        server
        for server in all_configs
        if server.get("protocol") == "udp"
    ]

    # ========================================================
    # CHECK INDIVIDUAL FILES
    # ========================================================

    if not tcp_servers:

        print(
            "ERROR: TCP server list is empty."
        )

        sys.exit(1)

    if not udp_servers:

        print(
            "ERROR: UDP server list is empty."
        )

        sys.exit(1)

    # ========================================================
    # SORT BY PING
    # ========================================================

    tcp_servers.sort(
        key=lambda server: numeric_value(
            server.get("ping")
        )
    )

    udp_servers.sort(
        key=lambda server: numeric_value(
            server.get("ping")
        )
    )

    all_configs.sort(
        key=lambda server: numeric_value(
            server.get("ping")
        )
    )

    # ========================================================
    # WRITE JSON FILES
    # ========================================================

    write_json(
        "tcp.json",
        tcp_servers
    )

    write_json(
        "udp.json",
        udp_servers
    )

    write_json(
        "all.json",
        all_configs
    )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 60)
    print("VPN SERVER UPDATE COMPLETE")
    print("=" * 60)

    print(
        f"Total servers : {len(all_configs)}"
    )

    print(
        f"TCP servers   : {len(tcp_servers)}"
    )

    print(
        f"UDP servers   : {len(udp_servers)}"
    )

    print()
    print("Generated files:")

    print(
        f"  tcp.json -> {len(tcp_servers)} servers"
    )

    print(
        f"  udp.json -> {len(udp_servers)} servers"
    )

    print(
        f"  all.json -> {len(all_configs)} servers"
    )

    print()
    print("Update completed successfully.")
    print("=" * 60)


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print("Update interrupted.")

        sys.exit(1)

    except Exception as e:

        print()
        print(
            f"FATAL ERROR: {e}"
        )

        sys.exit(1)
