import subprocess
import csv
import json
import os
import uuid
import requests
import logging
import time
from datetime import datetime
from collections import Counter

# ================================================
# CONFIGURATION
# ================================================

INTERFACE        = "eth0"
CAPTURE_DURATION = 20
THRESHOLD        = 30

PCAP_FILE     = "/tmp/traffic.pcap"
CSV_FILE      = "traffic.csv"
ALERT_FILE    = "alert.json"
RESPONSE_FILE = "gemini_response.json"
LOG_FILE      = "soc_log.txt"

GEMINI_API_KEY  = "YOUR_GEMINI_API_KEY_HERE"
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK_HERE"

DESTINATION_HOST = "kali-target"
DESTINATION_IP   = "10.0.2.2"

# ================================================
# LOGGING SETUP
# ================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ================================================
# SOC PLAYBOOK
# ================================================

SOC_PLAYBOOK = """
You are an enterprise Security Operations Center (SOC) Triage Analyst AI.

Your role is to analyze structured cybersecurity alert data provided in JSON format and produce a professional triage report following a defined SOC playbook.

You are a defensive security assistant only.

You must strictly follow the workflow and guardrails below.

------------------------------------------------------------
SECTION 1 — INPUT VALIDATION
------------------------------------------------------------

1. Confirm the input is valid JSON.
2. Ensure required fields exist:
   - alert_id
   - alert_type
   - indicator_type
   - indicator_value
   - source_host
   - destination_host
   - destination_ip
   - protocol
   - evidence.packet_count
   - evidence.time_window_seconds

------------------------------------------------------------
SECTION 2 — THREAT CLASSIFICATION
------------------------------------------------------------

Based strictly on the provided data, classify the likely activity as one of:

- Brute Force Attempt
- Network Reconnaissance / Scanning
- Suspicious Network Volume
- Possible Malware Communication
- Benign Network Noise
- Unknown

Do NOT invent additional context.
Do NOT assume facts not present in the alert.

------------------------------------------------------------
SECTION 3 — RISK SCORING MODEL (0-100)
------------------------------------------------------------

Assign a numeric risk score between 0 and 100 using this guidance:

Base Score Logic:
- Packet count > 30: +20
- Packet count > 50: +30
- Packet count > 100: +40
- Repeated activity within short time window (less than 60s): +20
- Privileged service target (if known): +20
- ICMP flood behavior: +15
- Suspicious login behavior: +25

Cap score at 100.

Then classify risk level:
0-29 → Low
30-59 → Medium
60-79 → High
80-100 → Critical

Explain how the score was calculated.

Do NOT fabricate additional indicators.

------------------------------------------------------------
SECTION 4 — MITRE ATT&CK MAPPING
------------------------------------------------------------

Map the activity to the most relevant MITRE ATT&CK tactic and technique.

Examples:
- T1110 — Brute Force (Credential Access)
- T1046 — Network Service Scanning
- T1071 — Application Layer Protocol
- T1498 — Network Denial of Service

If mapping is uncertain, return:
"mitre_mapping": "Uncertain based on available evidence"

Do not hallucinate obscure technique IDs.

------------------------------------------------------------
SECTION 5 — SOC ANALYST ACTION PLAN
------------------------------------------------------------

Provide clear, realistic Tier 1 actions:

- Monitor
- Enrich with threat intelligence
- Block IP
- Reset credentials
- Escalate to Tier 2
- Isolate host
- Review authentication logs

Actions must match risk level.

------------------------------------------------------------
SECTION 6 — ESCALATION LOGIC
------------------------------------------------------------

If risk score >= 80:
- Recommend immediate escalation to Tier 2
- Recommend containment action

If risk score between 60-79:
- Recommend analyst review + enrichment

If risk score below 60:
- Recommend monitoring unless pattern repeats

------------------------------------------------------------
SECTION 7 — EXECUTIVE SUMMARY
------------------------------------------------------------

Generate a short executive-level explanation:

- Plain language
- No technical jargon
- Focus on business impact
- 2-3 sentences maximum

------------------------------------------------------------
SECTION 8 — OUTPUT FORMAT (STRICT)
------------------------------------------------------------

You must respond ONLY in this structured JSON format:

{
  "alert_id": "",
  "threat_classification": "",
  "risk_score": 0,
  "risk_level": "",
  "confidence_level": "",
  "mitre_mapping": {
    "tactic": "",
    "technique_id": "",
    "technique_name": ""
  },
  "analysis_reasoning": "",
  "recommended_actions": [],
  "escalation_required": false,
  "executive_summary": ""
}

Do NOT include markdown.
Do NOT include conversational filler.
Do NOT speculate beyond provided data.

------------------------------------------------------------
SECTION 9 — CONFIDENCE LEVEL
------------------------------------------------------------

Assign:
- Low
- Medium
- High

Confidence must reflect completeness of input data.

------------------------------------------------------------
SECTION 10 — GUARDRAILS
------------------------------------------------------------

You must:

- Never provide attack instructions.
- Never generate exploit code.
- Never fabricate threat intelligence.
- Never assume attacker intent.
- Never invent missing telemetry.
- Maintain professional SOC tone.
- If uncertain, clearly state uncertainty.

You are a defensive security analysis system only.

End of instructions.
"""

# ================================================
# STARTUP CHECK
# ================================================

def startup_check():
    if not GEMINI_API_KEY or GEMINI_API_KEY == "PASTE_NEW_KEY_HERE":
        raise ValueError("Gemini API key is missing!")
    if os.geteuid() != 0:
        raise PermissionError(
            "Script must run as root. Use: sudo python3 soc_analyst.py"
        )
    with open(LOG_FILE, "a") as f:
        f.write("\n" + "=" * 60 + "\n")
        f.write(f" NEW SESSION — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n")
    log.info("Startup check passed. Running as root.")

# ================================================
# STEP 1 — Capture Traffic
# ================================================

def capture_traffic():
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"icmp and dst host {DESTINATION_IP}",
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]

    log.info(f"Capturing on '{INTERFACE}' for {CAPTURE_DURATION} seconds...")
    print("=" * 60)
    print("[!] OPEN A SECOND TERMINAL NOW AND RUN THE ATTACK:")
    print(f"    sudo hping3 -1 --flood -a 192.168.1.100 -I eth0 {DESTINATION_IP}")
    print("=" * 60)

    subprocess.run(capture_cmd, stderr=subprocess.DEVNULL)

    if not os.path.exists(PCAP_FILE) or os.path.getsize(PCAP_FILE) == 0:
        raise RuntimeError(
            "No packets captured. Make sure hping3 ran during the capture window."
        )

    log.info(f"Capture complete → {PCAP_FILE} ({os.path.getsize(PCAP_FILE)} bytes)")

# ================================================
# STEP 2 — Convert PCAP to CSV
# ================================================

def convert_to_csv():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    log.info(f"CSV created → {CSV_FILE}")

# ================================================
# STEP 3 — Analyze Traffic
# ================================================

def analyze_traffic():
    ip_counter = Counter()

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            if src_ip:
                ip_counter[src_ip] += 1

    if not ip_counter:
        log.info("No IP traffic found in capture.")
        return None, None

    log.info("Packet count per source IP:")
    for ip, count in ip_counter.most_common():
        log.info(f"  {ip} → {count} packets")

    for ip, count in ip_counter.most_common():
        if count > THRESHOLD:
            log.warning(f"SUSPICIOUS: {ip} sent {count} packets (threshold: {THRESHOLD})")
            return ip, count

    log.info(f"No IP exceeded threshold of {THRESHOLD}. No alert.")
    return None, None

# ================================================
# STEP 4 — Generate Alert JSON
# ================================================

def generate_alert(ip, count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id":         alert_id,
        "alert_type":       "Suspicious Network Volume",
        "indicator_type":   "ip",
        "indicator_value":  ip,
        "source_host":      "attacker-host",
        "destination_host": DESTINATION_HOST,
        "destination_ip":   DESTINATION_IP,
        "protocol":         "ICMP",
        "evidence": {
            "packet_count":        count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source":         PCAP_FILE
        }
    }

    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=4)

    log.info(f"Alert JSON saved → {ALERT_FILE}")
    return alert

# ================================================
# STEP 5 — Send to Gemini AI
# ================================================

def send_to_gemini(alert):
    log.info("Sending alert to Gemini AI for SOC triage...")

    prompt = SOC_PLAYBOOK + "\n\nAlert to analyze:\n" + json.dumps(alert, indent=2)

    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        f"models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    )

    for attempt in range(1, 4):
        try:
            log.info(f"Gemini API attempt {attempt} of 3...")
            response = requests.post(url, json=payload, timeout=60)

            if response.status_code == 429:
                wait = 30 * attempt
                log.warning(f"Rate limited. Waiting {wait} seconds then retrying...")
                time.sleep(wait)
                continue

            response.raise_for_status()
            break

        except requests.exceptions.RequestException as e:
            if attempt == 3:
                raise RuntimeError(f"Gemini API failed after 3 attempts: {e}")
            log.warning(f"Attempt {attempt} failed. Retrying in 30 seconds...")
            time.sleep(30)

    data = response.json()

    try:
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError):
        raise RuntimeError(f"Unexpected Gemini response format: {data}")

    raw_text = raw_text.strip()
    if raw_text.startswith("```"):
        raw_text = raw_text.split("\n", 1)[1]
        raw_text = raw_text.rsplit("```", 1)[0].strip()

    try:
        gemini_response = json.loads(raw_text)
    except json.JSONDecodeError:
        raise RuntimeError(f"Gemini did not return valid JSON:\n{raw_text}")

    with open(RESPONSE_FILE, "w") as f:
        json.dump(gemini_response, f, indent=4)

    log.info(f"Gemini response saved → {RESPONSE_FILE}")

    print("\n[+] ========== GEMINI SOC ANALYSIS ==========")
    print(json.dumps(gemini_response, indent=2))
    print("[+] ===========================================\n")

    return gemini_response

# ================================================
# STEP 6 — Auto Block via iptables
# ================================================

def auto_block(ip, risk_level):
    if risk_level in ["High", "Critical"]:
        log.warning(f"{risk_level.upper()} threat → Auto-blocking {ip} via iptables...")
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        )
        if result.returncode == 0:
            log.info(f"BLOCKED: All packets from {ip} are now dropped.")
        else:
            log.error("iptables block failed.")
    else:
        log.info(f"Risk level {risk_level} → Monitoring only. No block applied.")

# ================================================
# STEP 7 — Discord Alert
# ================================================

def send_discord_alert(alert_id, ip, risk_level, risk_score, classification):
    if not DISCORD_WEBHOOK:
        log.info("No Discord webhook set — skipping notification.")
        return

    emoji  = "🔴" if risk_level in ["High", "Critical"] else "🟡"
    action = "IP Auto-Blocked ✅" if risk_level in ["High", "Critical"] else "Monitoring 👀"

    message = {
        "content": (
            f"{emoji} **SOC ALERT — {risk_level.upper()}**\n"
            f"**Alert ID:** `{alert_id}`\n"
            f"**Classification:** {classification}\n"
            f"**Source IP:** `{ip}`\n"
            f"**Risk Score:** {risk_score}/100\n"
            f"**Action Taken:** {action}"
        )
    }

    try:
        r = requests.post(DISCORD_WEBHOOK, json=message, timeout=10)
        if r.status_code == 204:
            log.info("Discord alert sent successfully.")
        else:
            log.warning(f"Discord returned status: {r.status_code}")
    except Exception as e:
        log.error(f"Discord notification failed: {e}")

# ================================================
# MAIN
# ================================================

def main():
    print("=" * 60)
    print("     AI SOC ANALYST — Automated Threat Detection")
    print(f"     Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("     Press Ctrl+C to stop monitoring")
    print("=" * 60)

    try:
        startup_check()
    except Exception as e:
        log.error(f"Startup failed: {e}")
        return

    cycle = 1

    while True:
        try:
            log.info(f"--- Monitoring Cycle {cycle} started ---")

            capture_traffic()
            convert_to_csv()

            ip, count = analyze_traffic()

            if ip:
                alert           = generate_alert(ip, count)
                gemini_response = send_to_gemini(alert)

                risk_level     = gemini_response.get("risk_level", "Unknown")
                risk_score     = gemini_response.get("risk_score", 0)
                classification = gemini_response.get("threat_classification", "Unknown")
                alert_id       = gemini_response.get("alert_id") or alert["alert_id"]

                auto_block(ip, risk_level)
                send_discord_alert(alert_id, ip, risk_level, risk_score, classification)

                print("\n" + "=" * 60)
                print("   FINAL VERDICT")
                print(f"   IP:             {ip}")
                print(f"   Classification: {classification}")
                print(f"   Risk Score:     {risk_score}/100")
                print(f"   Risk Level:     {risk_level}")
                print(f"   Alert ID:       {alert_id}")
                print("=" * 60)
            else:
                log.info("Cycle clean — no threats detected.")

            log.info(f"--- Cycle {cycle} complete. Restarting in 5 seconds ---\n")
            cycle += 1
            time.sleep(5)

        except KeyboardInterrupt:
            print("\n[+] Monitoring stopped by user. Goodbye.")
            break

        except Exception as e:
            log.error(f"Error in cycle {cycle}: {e}")
            log.info("Restarting cycle in 10 seconds...")
            time.sleep(10)
            cycle += 1

if __name__ == "__main__":
    main()
