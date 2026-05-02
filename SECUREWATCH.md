
<div align="center">

```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ██║ █╗ ██║███████║   ██║   ██║     ███████║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

# SecureWatch SIEM
### Enterprise-Grade Security Information & Event Management

[![Version](https://img.shields.io/badge/version-4.0.0-blue?style=for-the-badge)](.)
[![Status](https://img.shields.io/badge/status-Production%20Ready-success?style=for-the-badge)](.)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](.)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)](.)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python)](.)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react)](.)

---

*Real vaqt kiberxavfsizlik monitoringi, avtomatik tahdid aniqlash va javob berish tizimi*

</div>

---

## Mundarija

- [Nima muammoni hal qiladi?](#-nima-muammoni-hal-qiladi)
- [Tizim imkoniyatlari](#-tizim-imkoniyatlari)
- [Arxitektura](#-arxitektura)
- [Deteksiya qoidalari](#-deteksiya-qoidalari-36-ta)
- [Agent monitoringi](#-agent-monitoringi-24-ta-collector)
- [Ishlov berish mexanizmi](#-ishlov-berish-mexanizmi)
- [Frontend sahifalar](#-frontend-16-ta-sahifa)
- [Texnik stack](#-texnik-stack)
- [Xavfsizlik xususiyatlari](#-xavfsizlik-xususiyatlari)
- [Biznes foydasi](#-biznes-foydasi)
- [Raqobatchilar bilan taqqoslash](#-raqobatchilar-bilan-taqqoslash)
- [O'rnatish](#-ornatish)

---

## ❗ Nima Muammoni Hal Qiladi?

Zamonaviy tashkilotlar har kuni minglab xavfsizlik hodisalari bilan to'qnashadi. Ularni qo'lda kuzatish **imkonsiz** — bitta muhim hujumni o'tkazib yuborish esa **millionlab zarar** keltirishi mumkin.

```
┌─────────────────────────────────────────────────────────────────┐
│              KIBERXAVFSIZLIK MUAMMOLARI                         │
├─────────────────┬───────────────────────────────────────────────┤
│  Muammo         │  Yechim                                       │
├─────────────────┼───────────────────────────────────────────────┤
│ Hujumlar        │ 36 ta qoida — real vaqtda aniqlash            │
│ sezilib qolmaydi│ + AI-asosida anomaliya deteksiyasi            │
├─────────────────┼───────────────────────────────────────────────┤
│ Javob berish    │ Active Response — avtomatik IP bloklash,       │
│ sekin           │ email xabarnoma, webhook triggerlar            │
├─────────────────┼───────────────────────────────────────────────┤
│ Log'lar         │ Elasticsearch — 90 kun saqlash,               │
│ ko'p, chalkash  │ 500+ format, real vaqt qidiruv                │
├─────────────────┼───────────────────────────────────────────────┤
│ Compliance      │ MITRE ATT&CK, CIS Benchmark, STIG —          │
│ talablari       │ avtomatik hisobotlar                           │
├─────────────────┼───────────────────────────────────────────────┤
│ Ko'p server     │ Bitta panel — Windows, Linux, macOS,          │
│ boshqaruvi      │ Docker, Kubernetes agentlari                  │
└─────────────────┴───────────────────────────────────────────────┘
```

### Hal qilinadigan tahdidlar

| # | Tahdid | Aniqlash usuli |
|---|--------|---------------|
| 1 | **SSH Brute Force** | 5+ muvaffaqiyatsiz urinish / 60 soniya |
| 2 | **Password Spray** | 20+ muvaffaqiyatsiz urinish / 5 daqiqa |
| 3 | **Rootkit** | Yashirin jarayonlar, LD_PRELOAD hijack |
| 4 | **Privilege Escalation** | Sudo, sudoers o'zgartirish, root login |
| 5 | **Persistence** | Yangi foydalanuvchilar, SSH kalitlar, cron |
| 6 | **Konfiguratsiya o'zgarishi** | /etc/passwd, sshd_config, sudoers FIM |
| 7 | **Malware** | Reverse shell, DNS tunneling, DGA domenlar |
| 8 | **Zaifliklari** | CVE bazasi bilan paket versiyalarni tekshirish |
| 9 | **Ma'lumot o'g'irlash** | USB qurilma, shubhali ulanishlar |
| 10 | **Compliance buzilishi** | CIS Level 1, STIG 50+ tekshiruv |
| 11 | **Container hujumlari** | Docker lifecycle, image o'zgarishlari |
| 12 | **Web hujumlar** | SQLi, XSS, Path Traversal, skannerlar |

---

## 🚀 Tizim Imkoniyatlari

### Asosiy modullar

```
SecureWatch SIEM
│
├── 🔍 DETECTION ENGINE
│   ├── 36 ta tayyor qoida (CRITICAL/HIGH/MEDIUM/LOW)
│   ├── Regex + field-value + frequency qoidalar
│   ├── Welford algoritmi asosida anomaliya deteksiyasi
│   └── Ko'p hodisa korrelyatsiyasi (brute force zanjiri, escalation→persistence)
│
├── 🤖 ACTIVE RESPONSE
│   ├── Avtomatik IP bloklash (sozlanuvchi vaqt)
│   ├── Email + Slack + Webhook xabarnomalar
│   └── Avtomatik blokning o'chirilishi (timeout)
│
├── 📊 LOG MANAGEMENT
│   ├── 500+ log formatini qo'llab-quvvatlash
│   ├── Elasticsearch'da 90 kun saqlash
│   ├── Real vaqt qidiruv va filtrlash
│   └── CSV / JSON eksport
│
├── 🕵️ THREAT INTELLIGENCE
│   ├── AbuseIPDB, VirusTotal, Firehol integratsiya
│   ├── GeoIP boyitish (mamlakat, shahar, ASN)
│   ├── DNS monitoring (tunneling, DGA)
│   └── IOC (Indicator of Compromise) boshqaruvi
│
├── 🛡️ COMPLIANCE
│   ├── MITRE ATT&CK taktika/texnika teglash
│   ├── CIS Benchmark Level 1 (50+ tekshiruv)
│   ├── STIG muvofiqlik tekshiruvi
│   └── To'liq audit trail
│
├── 📦 VULNERABILITY MANAGEMENT
│   ├── NVD (NIST) CVE bazasi integratsiyasi
│   ├── dpkg, rpm, pip, npm, Windows Registry paketlar
│   └── Zaiflik holati kuzatuvi + remediation
│
├── 📋 INCIDENT MANAGEMENT
│   ├── Case management (Jira-ga o'xshash)
│   ├── Alert → Case bog'lash
│   ├── Izohlar, tayinlash, holat kuzatuvi
│   └── SLA monitoring
│
└── 🌐 REAL-TIME DASHBOARD
    ├── WebSocket orqali jonli alertlar
    ├── 16 ta interaktiv sahifa
    ├── Ko'p til va tema qo'llab-quvvatlash
    └── Grafana + Prometheus monitoring
```

---

## 🏗️ Arxitektura

```
                         ┌─────────────────────────────┐
                         │        INTERNET / LAN        │
                         └──────────────┬──────────────┘
                                        │
                    ┌───────────────────▼──────────────────┐
                    │            NGINX (Reverse Proxy)      │
                    │   Port 8080 (HTTP) · 8443 (HTTPS)    │
                    │   Rate limiting · Security headers    │
                    └──────┬─────────────────┬─────────────┘
                           │                 │
              ┌────────────▼──┐         ┌────▼──────────────┐
              │   FRONTEND    │         │     BACKEND        │
              │   React 18    │         │   FastAPI + Python │
              │   TailwindCSS │         │   4 Workers        │
              │   WebSocket   │         │   100+ API Endpoints│
              └───────────────┘         └────┬──────┬────────┘
                                             │      │
                        ┌────────────────────┘      └─────────────────┐
                        │                                              │
           ┌────────────▼──────────┐                    ┌─────────────▼──────┐
           │     DATA LAYER        │                    │   CACHE LAYER       │
           │                       │                    │                     │
           │  PostgreSQL 15        │                    │  Redis 7            │
           │  (Users, Rules,       │◄──────────────────►│  (Sessions, Rate    │
           │   Alerts, Cases,      │   Sync 300s        │   limits, Baselines,│
           │   Audit logs)         │                    │   WS pub/sub)       │
           └───────────────────────┘                    └─────────────────────┘
                        │
           ┌────────────▼──────────────────┐
           │        Elasticsearch 8.11      │
           │   Log storage · ILM policies   │
           │   Full-text search · Analytics │
           │   90-day retention · Sharding  │
           └────────────────────────────────┘

AGENTS (tarmoqdagi serverlar):
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│  Linux   │  │ Windows  │  │  macOS   │  │  Docker  │  │   K8s    │
│  Agent   │  │  Agent   │  │  Agent   │  │  Agent   │  │  Agent   │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     └──────────────┴─────────────┴──────────────┴─────────────┘
                                  │
                    HTTP/HTTPS → Backend :8080
                    (Buffered offline storage — SQLite)
```

---

## 🎯 Deteksiya Qoidalari (36 ta)

### Qoidalar bo'yicha taqsimot

```
JIDDIYLIK DARAJASI:

  CRITICAL  ████████████████████  8 ta qoida
  HIGH      ███████████████████████████  11 ta qoida
  MEDIUM    ████████████████████████████████  12 ta qoida
  LOW       ████████████  5 ta qoida
```

### Kategoriyalar

| Kategoriya | Qoidalar | Misol |
|-----------|---------|-------|
| 🔐 Autentifikatsiya | 6 | SSH brute force, noto'g'ri foydalanuvchi, root login |
| ⬆️ Imtiyoz oshirish | 4 | Sudo foydalanish, sudoers o'zgartirish |
| 🦠 Rootkit / Zararli dastur | 5 | Yashirin jarayonlar, LD_PRELOAD, kernel modullar |
| 📁 Fayl yaxlitligi | 4 | Kritik fayllar o'zgarishi/o'chirilishi |
| 🌐 Tarmoq | 2 | Firewall bloklash, port skanerlash |
| 🕸️ Web hujumlar | 2 | SQLi, XSS, path traversal |
| 💪 Brute Force | 3 | SSH, parol sprey, root SSH |
| 💥 Mavjudlik | 3 | Servis crash, OOM killer, kernel panic |
| 🔧 Boshqa | 7 | AppArmor, USB, container hodisalar |

### Chastota asosida qoidalar

```python
# Misol: SSH Brute Force aniqlash
Shart: 5+ muvaffaqiyatsiz urinish / 60 soniya ichida
Harakat: IP ni bloklash (3600 soniya)
MITRE: T1110.001 — Brute Force: Password Guessing
```

---

## 🤖 Agent Monitoringi (24 ta Collector)

### Qo'llab-quvvatlanadigan platformalar

```
┌─────────────────────────────────────────────────────┐
│                  AGENT QAMROVI                      │
├─────────────┬───────────────────────────────────────┤
│  Linux      │ Ubuntu 20+, Debian 11+, RHEL 8+,      │
│             │ Amazon Linux 2/2023, Fedora 36+        │
├─────────────┼───────────────────────────────────────┤
│  Windows    │ Windows 10/11, Server 2016/2019/2022   │
│             │ Task Scheduler (pywin32 DLL yo'q)      │
├─────────────┼───────────────────────────────────────┤
│  macOS      │ macOS 12+ (Monterey), Intel + M-chip   │
│             │ LaunchDaemon orqali avtomatik ishga    │
│             │ tushish                                │
├─────────────┼───────────────────────────────────────┤
│  Docker     │ Konteyner lifecycle, log, image        │
├─────────────┼───────────────────────────────────────┤
│  Kubernetes │ Pod/Deployment hodisalar               │
└─────────────┴───────────────────────────────────────┘
```

### Collectorlar ro'yxati

#### Log To'plash
| Collector | Tavsif |
|-----------|--------|
| `log_collector.py` | Fayl log'lari (syslog, auth.log, nginx, JSON) |
| `journald_collector.py` | Linux systemd journald hodisalar |
| `windows_events.py` | Windows Event Log (300+ event ID, 29 Sysmon turi) |
| `macos_collector.py` | macOS unified logging + BSM audit |
| `auditd_collector.py` | Linux auditd SYSCALL, EXECVE, PATH hodisalar |

#### Tizim Monitoringi
| Collector | Tavsif |
|-----------|--------|
| `system_collector.py` | CPU, RAM, disk, tarmoq metrikalari |
| `process_monitor.py` | Yangi jarayonlar, imtiyoz o'zgarishlari |
| `network_monitor.py` | Shubhali ulanishlar, C2 beacon aniqlash |
| `dns_monitor.py` | DNS tunneling, DGA domenlar, shubhali TLD |

#### Xavfsizlik
| Collector | Tavsif |
|-----------|--------|
| `file_integrity.py` | FIM — SHA-256 baseline + tekshiruv |
| `fim_realtime.py` | Real vaqt FIM (inotify/FSEvents/ReadDirChangesW) |
| `windows_registry_fim.py` | Registry kalit o'zgarishlari (persistence kalitlar) |
| `rootcheck.py` | Yashirin jarayonlar, SUID/SGID, kernel modullar |
| `windows_service_monitor.py` | Servis o'rnatish, binary-path o'zgarishlari |

#### Zaiflik va Compliance
| Collector | Tavsif |
|-----------|--------|
| `vuln_scanner.py` | dpkg, rpm, pip, npm, Windows Registry paketlar |
| `sca_collector.py` | CIS Benchmark Level 1 + STIG (50+ tekshiruv) |

#### Inventarizatsiya
| Collector | Tavsif |
|-----------|--------|
| `inventory_collector.py` | Paketlar, portlar, jarayonlar, interfeys delta |
| `docker_collector.py` | Docker lifecycle, loglar, image boshqaruvi |

#### Boyitish
| Collector | Tavsif |
|-----------|--------|
| `geoip.py` | IP geolokatsiya (mamlakat, shahar, ASN) |
| `threat_intel.py` | IP reputatsiya (AbuseIPDB, Firehol) |
| `correlation.py` | Ko'p hodisa korrelyatsiyasi |
| `dedup.py` | Hodisa deduplikatsiyasi (rolling window) |

### Agent xususiyatlari

```
Oflayn bufer:   SQLite + gzip siqish
                Server o'chsa — ma'lumot yo'qolmaydi
                Qayta ulanganda avtomatik jo'natish

Ishlash:        Batch hajmi: 100 hodisa
                Yurak urishi: 30 soniya
                CPU: < 0.5%
                RAM: < 256 MB

O'rnatish:      Bir buyruq (Linux/macOS: curl | bash)
                (Windows: PowerShell one-liner)
```

---

## ⚙️ Ishlov Berish Mexanizmi

### Log qayta ishlash quvuri

```
Log kelishi
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  1. DECODER — 500+ format qo'llab-quvvatlash        │
│     syslog, CEF, JSON, Windows XML, nginx, Apache   │
│     auditd, journald, Docker, Kubernetes            │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  2. THREAT INTEL BOYITISH                           │
│     • IP reputatsiya (AbuseIPDB, Firehol)           │
│     • GeoIP (mamlakat, shahar, ASN)                 │
│     • Domain tekshiruvi (VirusTotal)                │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  3. QOIDA TEKSHIRUVI                                │
│     • Regex moslashtirish                           │
│     • Field-value shartlar                          │
│     • Raqamli taqqoslash (>=400, <500)              │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  4. CHASTOTA TAHLILI (Sliding Window)               │
│     • N ta hodisa / M sekund ichida                 │
│     • Per-agent hisoblagich                         │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  5. ANOMALIYA DETEKSIYASI (Welford algoritmi)       │
│     • Z-score > 3.0 → HIGH                         │
│     • Z-score > 2.0 → MEDIUM                       │
│     • O(1) xotira sarfi                             │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  6. KORRELYATSIYA                                   │
│     • SSH brute force → muvaffaqiyatli login        │
│     • Port skan → kirish urinishi                   │
│     • Imtiyoz oshirish → persistence                │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  7. MITRE ATT&CK TEGLASH                            │
│     Har bir alert uchun: Taktika + Texnika          │
│     Misol: TA0006 (Credential Access) + T1110.001   │
└──────────────────────┬──────────────────────────────┘
                       │
    ▼
┌─────────────────────────────────────────────────────┐
│  8. ALERT YARATISH (Aggregatsiya + Cooldown)        │
│     • 24 soat ichida bir xil alert → birlashtirish  │
│     • Cooldown (flood oldini olish)                 │
│     • SHA-256 hash asosida agg_key                  │
└──────────────────────┬──────────────────────────────┘
                       │
    ├──► PostgreSQL (saqlash)
    ├──► Elasticsearch (qidiruv)
    ├──► WebSocket (real vaqt UI)
    ├──► Active Response (avtomatik harakat)
    └──► Notification (email/Slack/webhook)
```

---

## 🖥️ Frontend (16 ta Sahifa)

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECUREWATCH DASHBOARD                        │
├──────────────┬──────────────────────────────────────────────────┤
│              │                                                  │
│  📊 Dashboard│  Umumiy ko'rinish, metrikalar, tizim holati      │
│  🖥️ Agents  │  Agent holati, oxirgi yurak urishi, versiya      │
│  🚨 Alerts  │  Alert brauzer, filtrlash, tayinlash, yechish    │
│  📋 Logs    │  Log qidiruv, timeline, eksport                  │
│  📏 Rules   │  Qoida yaratish, tahrirlash, sinash              │
│  ⚡ Active   │  Javob siyosatlari, ijro kuzatuvi               │
│    Response  │                                                  │
│  🔍 Threat  │  IOC boshqaruvi, IP/domain tekshiruv            │
│    Intel     │                                                  │
│  🔓 Vulns   │  Zaiflik kuzatuvi, remediation                  │
│  📋 SCA     │  Compliance tekshiruvi natijalari                │
│  📦 Inventory│  Paketlar, portlar, jarayonlar, interfeys        │
│  🔗 Correl. │  Ko'p hodisa pattern qoidalari                  │
│  📁 Cases   │  Insidentlarni boshqarish, alert bog'lash        │
│  📜 Audit   │  Foydalanuvchi amallari tarixi                   │
│  📊 Reports │  CSV/JSON eksport, umumiy hisobotlar             │
│  ⚙️ Settings│  Profil, 2FA, TOTP, bildirishnomalar             │
│              │                                                  │
└──────────────┴──────────────────────────────────────────────────┘
```

### UI xususiyatlari

- **Real-time:** WebSocket orqali jonli alertlar (push notification)
- **Ko'p til:** i18n qo'llab-quvvatlash
- **Tema:** Qora / Oq rejim
- **Responsive:** Telefon, planshet, kompyuter
- **2FA/TOTP:** Google Authenticator bilan login
- **Backup koding:** TOTP yo'qolsa backup kodlar

---

## 🔧 Texnik Stack

### Backend

| Komponent | Texnologiya | Versiya |
|-----------|-------------|---------|
| Framework | FastAPI | 0.110+ |
| Ma'lumotlar bazasi | PostgreSQL | 15 |
| Qidiruv / Log | Elasticsearch | 8.11 |
| Kesh | Redis | 7 |
| ORM | SQLAlchemy (async) | 2.0+ |
| Autentifikatsiya | JWT + TOTP | — |
| WebSocket | FastAPI WebSocket | — |

### Frontend

| Komponent | Texnologiya |
|-----------|-------------|
| Framework | React 18 |
| Stil | TailwindCSS |
| HTTP | Axios (retry + backoff) |
| Routing | React Router v6 |
| Charts | Recharts |
| Bundler | Vite |

### Infratuzilma

```yaml
Xizmatlar:
  - nginx:alpine          # Reverse proxy, rate limiting
  - python:3.11-slim      # Backend
  - node:20-alpine        # Frontend build
  - postgres:15-alpine    # Ma'lumotlar bazasi (1GB RAM)
  - elasticsearch:8.11.0  # Log saqlash (3GB RAM, 2GB heap)
  - redis:7-alpine        # Kesh, sessiyalar (512MB)
  - prom/prometheus       # Metrikalar (30 kun saqlash)
  - prom/alertmanager     # Alert yo'naltirish
  - grafana/grafana       # Vizualizatsiya
```

### Resurs talablari

```
Minimal:
  RAM:  8 GB
  CPU:  4 core
  Disk: 100 GB SSD

Tavsiya etilgan:
  RAM:  16 GB
  CPU:  8 core
  Disk: 500 GB SSD (NVMe)

Enterprise:
  RAM:  32 GB+
  CPU:  16 core+
  Disk: 2 TB+ (Elasticsearch alohida cluster)
```

---

## 🔒 Xavfsizlik Xususiyatlari

### Autentifikatsiya va Avtorizatsiya

```
✅ JWT Access Token (60 daqiqa)
✅ Refresh Token (7 kun)
✅ TOTP 2FA (Google Authenticator)
✅ TOTP Backup kodlari
✅ Parol siyosati (12+ belgi, katta/kichik harf, raqam, maxsus belgi)
✅ Brute force himoyasi (login uchun rate limiting: 20/daqiqa)
✅ Token blacklist (Redis'da logout)
✅ Audit trail (barcha amallari qayd etiladi)
```

### API Xavfsizlik

```
✅ Rate Limiting:
   Auth endpointlar:    20 so'rov/daqiqa
   Log ingest:         600 so'rov/daqiqa
   Umumiy API:         300 so'rov/daqiqa

✅ CORS (sozlanuvchi)
✅ Security headers (X-Frame-Options, CSP, HSTS)
✅ Request ID kuzatuvi
✅ Structured JSON logging
✅ SQL Injection himoyasi (SQLAlchemy ORM)
✅ ReDoS himoyasi (regex validatsiya)
```

### Infratuzilma

```
✅ Elasticsearch X-Pack Security
✅ Redis auth (parol himoyasi)
✅ PostgreSQL connection pooling
✅ Agent Secret autentifikatsiyasi
✅ Barcha portlar localhost'ga bog'langan
✅ Docker network izolyatsiyasi
```

### Monitoring

```
✅ 7 ta Prometheus alert qoidasi:
   • Backend tushib qolsa (1 daqiqa ichida xabar)
   • Elasticsearch tushib qolsa (2 daqiqa ichida)
   • Cluster RED holati
   • 5xx xatolik darajasi > 5%
   • Xotira iste'moli > 85%
   • Disk to'lib qolsa (< 15% qolsa)
   • Agent yurak urishi yo'qolsa

✅ Grafana dashboard
✅ Alertmanager (webhook + email routing)
✅ Tizim sog'ligi tekshiruvi (/api/health)
```

---

## 💼 Biznes Foydasi

### Moliyaviy tejash

```
┌─────────────────────────────────────────────────────────────┐
│                  NARX TAQQOSI                               │
├──────────────────────────────┬──────────────────────────────┤
│  Tijorat SIEM (Splunk/QRadar)│  SecureWatch SIEM            │
├──────────────────────────────┼──────────────────────────────┤
│  $50,000 - $200,000/yil      │  O'z serveringizda bepul     │
│  + litsenziya cheklovlari    │  + cheksiz agent             │
│  + agent litsenziyalari      │  + cheksiz log hajmi         │
│  + ma'lumot hajmi limiti     │  + manba kodi ochiq          │
└──────────────────────────────┴──────────────────────────────┘
```

### Operatsion samaradorlik

| Jarayon | Avval (qo'lda) | Keyin (avtomatik) |
|---------|----------------|-------------------|
| Brute force aniqlash | 30-60 daqiqa | **< 60 sekund** |
| IP bloklash | 15-20 daqiqa | **Avtomatik** |
| Compliance hisobot | 2-3 kun | **Bir tugma** |
| Log qidiruv | Soatlab | **< 1 sekund** |
| Zaiflik tekshiruvi | Haftalik qo'lda | **Kunlik avtomatik** |

### Xavf kamaytirish

```
Dwell time (hujumchi tizimda qolish vaqti):
  Sanoat o'rtacha:        197 kun
  SecureWatch SIEM bilan: < 1 soat (real vaqt aniqlash)

Data breach narxi (IBM 2024):
  O'rtacha:  $4.45 million
  Erta aniqlash bilan: 35% kamroq zarar = $1.56 million tejash
```

---

## 📊 Raqobatchilar Bilan Taqqoslash

```
┌─────────────────┬────────────┬──────────┬───────────┬──────────────┐
│  Xususiyat      │ Splunk     │ QRadar   │ Wazuh     │ SecureWatch  │
├─────────────────┼────────────┼──────────┼───────────┼──────────────┤
│  Narx           │ $$$$       │ $$$$     │ Bepul     │ Bepul        │
│  O'rnatish      │ Murakkab   │ Murakkab │ O'rta     │ ✅ Oddiy     │
│  UI             │ Yaxshi     │ O'rta    │ Yaxshi    │ ✅ Ajoyib    │
│  Active Response│ Qo'shimcha │ Ha       │ Ha        │ ✅ Ha        │
│  Anomaliya      │ ML (to'lov)│ Ha       │ Ha        │ ✅ Ha        │
│  Windows agent  │ Ha         │ Ha       │ Ha*       │ ✅ Ha        │
│  Docker native  │ O'rta      │ O'rta    │ O'rta     │ ✅ To'liq    │
│  Case mgmt      │ To'lov     │ Ha       │ Yo'q      │ ✅ Ha        │
│  2FA/TOTP       │ To'lov     │ Ha       │ To'lov    │ ✅ Ha        │
│  Manba kodi     │ Yopiq      │ Yopiq    │ Ochiq     │ ✅ Ochiq     │
└─────────────────┴────────────┴──────────┴───────────┴──────────────┘
* Wazuh Windows agent'da DLL muammolari mavjud
```

---

## 📦 O'rnatish

### Tezkor o'rnatish (5 daqiqa)

```bash
# 1. Repozitoriyani yuklab olish
git clone https://github.com/DiorDevv/SIEM.git
cd SIEM

# 2. Muhit sozlamalari
cp .env.example .env

# 3. Maxfiy kalitlarni yaratish
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"

# 4. .env faylini tahrirlash
nano .env
# SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD, ELASTIC_PASSWORD

# 5. Ishga tushirish
docker compose up -d --build

# 6. Holat tekshirish
docker compose ps
```

### Saytga kirish

```
Dashboard:   http://your-server:8080
Admin login: admin / Admin@SIEM2024!
Grafana:     http://your-server:3001
Prometheus:  http://your-server:9090
```

### Agent o'rnatish

**Linux:**
```bash
curl -fsSL "http://your-server:8080/api/installer/linux?\
manager_url=http://your-server:8080&agent_name=my-server" | sudo bash
```

**Windows (PowerShell, Administrator):**
```powershell
$url="http://your-server:8080/api/installer/windows?manager_url=http://your-server:8080&agent_name=my-pc"
iwr $url -UseBasicParsing -OutFile "$env:TEMP\Install-SIEMAgent.ps1"
& "$env:TEMP\Install-SIEMAgent.ps1"
```

**macOS:**
```bash
curl -fsSL "http://your-server:8080/api/installer/macos?\
manager_url=http://your-server:8080&agent_name=my-mac" | sudo bash
```

---

## 📈 Kelajak Yo'nalishlar

```
v4.1 (Rejalashtirilgan):
  □ PostgreSQL Streaming Replication (HA)
  □ Elasticsearch 3-node cluster
  □ Redis Sentinel
  □ Alembic DB migratsiyalari
  □ Unit + Integration testlar

v4.2:
  □ OpenTelemetry distributed tracing
  □ AI-based threat hunting (LLM integratsiya)
  □ Yandex / Telegram xabarnoma kanali
  □ SOAR integratsiya
  □ Multi-tenant arxitektura

Enterprise:
  □ SAML / SSO (Active Directory)
  □ Multi-region deployment
  □ Custom ML modellar
  □ API Gateway
```

---

<div align="center">

---

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   SecureWatch SIEM — Xavfsizlik hech qachon uxlamaydi    ║
║                                                           ║
║   GitHub: https://github.com/DiorDevv/SIEM               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

**Versiya:** 4.0.0 &nbsp;|&nbsp; **Sana:** 2026 &nbsp;|&nbsp; **Litsenziya:** MIT

</div>
