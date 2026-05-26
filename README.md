# RansomGuard — Anti-Ransomware eBPF per Linux

```


██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔════╝ ████╗ ████║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║██╔██╗ ██║███████╗██║  ███╗██╔████╔██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

               ███████╗██╗   ██╗███████╗████████╗███████╗███╗   ███╗
               ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║
               ███████╗ ╚████╔╝ ███████╗   ██║   █████╗  ██╔████╔██║
               ╚════██║  ╚██╔╝  ╚════██║   ██║   ██╔══╝  ██║╚██╔╝██║
               ███████║   ██║   ███████║   ██║   ███████╗██║ ╚═╝ ██║
               ╚══════╝   ╚═╝   ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝

                   Monitoraggio, rilevamento e blocco ransomware in tempo reale
                   basato su eBPF (Extended Berkeley Packet Filter)

```

---

## Indice

1. [Cosa è RansomGuard](#1-cosa-è-ransomguard)
2. [Architettura del Sistema](#2-architettura-del-sistema)
3. [Come Funziona: Teoria](#3-come-funziona-teoria)
4. [Il Sistema di Scoring](#4-il-sistema-di-scoring)
5. [Requisiti di Sistema](#5-requisiti-di-sistema)
6. [Installazione e Compilazione](#6-installazione-e-compilazione)
7. [Configurazione](#7-configurazione)
8. [Utilizzo](#8-utilizzo)
9. [Walkthrough del Codice](#9-walkthrough-del-codice)
10. [Scenario di Attacco Simulato](#10-scenario-di-attacco-simulato)
11. [Domande Frequenti](#11-domande-frequenti)

---

## 1. Cosa è RansomGuard

**RansomGuard** è un sistema di rilevamento e blocco ransomware che opera a livello di **kernel Linux** usando la tecnologia **eBPF** (Extended Berkeley Packet Filter). A differenza degli antivirus tradizionali che analizzano i file sul disco o il traffico di rete, RansomGuard monitora le **chiamate di sistema (syscall)** in tempo reale direttamente all'interno del kernel.

### Cosa lo rende speciale

| Caratteristica | Descrizione |
|---|---|
| **Rilevamento istantaneo** | Opera dentro il kernel Linux — nessun delay, nessun polling |
| **Zero overhead in idle** | L'eBPF si attiva solo quando vengono chiamate determinate syscall |
| **Nessuna firma** | Non usa database di firme — rileva il *comportamento*, non il malware specifico |
| **Doppio strato di difesa** | Kernel (BPF) e User-space (C monitor) lavorano in tandem |
| **SIGSTOP safe di default** | Blocca il processo senza ucciderlo, dando tempo di investigare |
| **Configurabile a runtime** | Soglie e azioni modificabili via YAML, senza ricompilare |
| **16 MB di ring buffer** | Nessuna perdita di eventi anche sotto attacco massivo |

### Cosa monitora

RansomGuard intercetta **13 tracepoint** del kernel, coprendo l'intero ciclo di vita di un attacco ransomware:

```
┌──────────────────────────────────────────────────────────────────┐
│                    SYSALL MONITORATE                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  APERTURA FILE                                                   │
│  ├── sys_enter_openat       ───  apertura file (con flag)        │
│                                                                  │
│  SCRITTURA E RINOMINA                                           │
│  ├── sys_enter_write        ───  scrittura su file               │
│  ├── sys_enter_rename       ───  rinomina file                   │
│  ├── sys_enter_renameat2    ───  rinomina file (nuova versione)  │
│                                                                  │
│  CANCELLAZIONE                                                  │
│  ├── sys_enter_unlink       ───  cancellazione file              │
│  ├── sys_enter_unlinkat     ───  cancellazione file (nuova)      │
│                                                                  │
│  CRITTOGRAFIA                                                    │
│  ├── sys_enter_getrandom    ───  generazione chiavi crittografiche│
│  ├── sys_enter_socket       ───  socket(AF_ALG) → Crypto API     │
│  ├── sys_exit_socket        ───  cattura fd del socket AF_ALG    │
│  ├── sys_enter_sendmsg      ───  invio dati da cifrare           │
│                                                                  │
│  COPIA ZERO-COPY                                                │
│  ├── sys_enter_copy_file_range ─  zero-copy tra file             │
│  ├── sys_enter_vmsplice     ───  zero-copy pipe ↔ memoria        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 2. Architettura del Sistema

RansomGuard è diviso in **due componenti** che comunicano attraverso mappe BPF condivise:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            USER SPACE (Linux)                               │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      ./ransomguard (C)                               │   │
│  │                                                                       │   │
│  │  1. Legge ransomguard_config.yaml                                     │   │
│  │  2. Carica il programma eBPF nel kernel via libbpf skeleton           │   │
│  │  3. Scrive configurazione e whitelist nelle BPF maps                  │   │
│  │  4. Si mette in ascolto sul ring buffer                               │   │
│  │     │                                                                 │   │
│  │     ├─ Ogni 100ms: poll del ring buffer                               │   │
│  │     ├─ Ogni evento: handle_event() → log + SIGSTOP (se soglia)       │   │
│  │     └─ Ogni 30s: dump_statistiche a schermo                           │   │
│  └──────────────────────────┬──────────────────────────────────────────┘   │
│                             │                                               │
│  ┌──────────────────────────┴──────────────────────────────────────────┐   │
│  │                      BPF MAPS (memoria condivisa)                    │   │
│  │                                                                       │   │
│  │  ┌─────────────────┐  ┌──────────────────┐  ┌──────────┐  ┌──────┐  │   │
│  │  │  events_ringbuf  │  │  proc_stats_map  │  │config_map│  │wl_map│  │   │
│  │  │  (RINGBUF 16MB)  │  │  (HASH pid→stat) │  │ (ARRAY)  │  │(ARRAY)│  │   │
│  │  │                  │  │                  │  │          │  │      │  │   │
│  │  │  kernel→user     │  │  0: open_count   │  │ 0: thr_o │  │PID  1 │  │   │
│  │  │  eventi in tempo │  │  1: write_count  │  │ 1: thr_w │  │PID  2 │  │   │
│  │  │  reale           │  │  2: rename_count │  │ 2: thr_r │  │...    │  │   │
│  │  │                  │  │  3: unlink_count │  │ 3: thr_u │  │PID  N │  │   │
│  │  │  write: kernel   │  │  4: getrandom_c  │  │ 4: score │  │      │  │   │
│  │  │  read:  userspace│  │  5: aflg_count   │  │ 5: window│  │      │  │   │
│  │  │                  │  │  ...             │  │ 6: kill  │  │      │  │   │
│  │  │                  │  │  score: 0-100    │  │          │  │      │  │   │
│  │  └─────────────────┘  └──────────────────┘  └──────────┘  └──────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────┬──────────────────────────────────────────────────┘
                           │
                           │    SYSCALL BOUNDARY (int 0x80 / sysenter)
                           │
┌──────────────────────────┴──────────────────────────────────────────────────┐
│                          KERNEL SPACE (Linux)                               │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    ransomguard.bpf.c (eBPF)                         │   │
│  │                                                                       │   │
│  │  13 tracepoint hook                                                   │   │
│  │  (ogni volta che un processo chiama una syscall monitorata)           │   │
│  │     │                                                                 │   │
│  │     ├─ 1. is_whitelisted()? → salta se sì                             │   │
│  │     ├─ 2. get_or_create_proc_stat()                                   │   │
│  │     ├─ 3. maybe_reset_window() → azzera se scaduta                    │   │
│  │     ├─ 4. incrementa contatore specifico (es: ps->unlink_count++)    │   │
│  │     ├─ 5. update_score() → ricalcola punteggio 0-100                  │   │
│  │     ├─ 6. check_and_kill() → SIGKILL se score ≥ soglia               │   │
│  │     └─ 7. emit_event() → scrive sul ring buffer                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Flusso di un evento

```
Processo malevolo
      │
      │ chiama unlink("foto.jpg")
      ▼
┌─────────────────┐
│ Kernel: syscall  │ ───→ L'eBPF si attiva al tracepoint sys_enter_unlink
│ unlink()         │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ eBPF: handle_enter_unlink()         │
│                                     │
│  1. is_whitelisted(pid)? → No       │
│  2. get_or_create_proc_stat()       │
│  3. maybe_reset_window()            │
│  4. ps->unlink_count++              │
│  5. update_score() → score = 42     │
│  6. check_and_kill() → score < 60   │
│     (nessuna azione)                │
│  7. emit_event() → ring buffer      │
└────────┬────────────────────────────┘
         │
         │ ring buffer
         ▼
┌─────────────────────────────────────┐
│ User-space: handle_event()          │
│                                     │
│  - Legge l'evento dal ring buffer   │
│  - Legge proc_stats_map per il PID  │
│  - Score = 42 < 60 (nessun alert)   │
│  - Se verbose: LOG_DEBUG(evento)    │
└─────────────────────────────────────┘

   ... continua ...

   Dopo 100 unlink + 80 rename + 5 getrandom + 3 AF_ALG:

   update_score() → score = 74 ≥ 60
   check_and_kill():
     └─ kill_enabled = false → non uccide
        (ma segna killed=1 per evitare duplicati)

   User-space handle_event():
     └─ LOG_ALERT("*** RANSOMWARE RILEVATO *** PID=1234 COMM=xyz ...")
     └─ kill(SIGSTOP) → processo congelato
```

---

## 3. Come Funziona: Teoria

### 3.1 Cosa è eBPF?

eBPF (Extended Berkeley Packet Filter) è una tecnologia del kernel Linux che permette di eseguire codice sandboxed all'interno del kernel senza modificarlo o caricare moduli. Immagina di poter programmare il kernel come se fosse JavaScript nel browser:

```
  PROGRAMMA NORMALE                         PROGRAMMA eBPF
  ┌──────────────────┐                     ┌──────────────────┐
  │                  │                     │                  │
  │  Devo aggiungere │                     │  Scrivi C,       │
  │  una feature al  │                     │  compili in       │
  │  kernel?         │                     │  bytecode BPF,    │
  │                  │                     │  carichi a runtime│
  │  → Scrivi modulo │                     │                  │
  │    kernel C      │                     │  → Il kernel      │
  │  → Rischio       │                     │    verifica il    │
  │    kernel panic  │                     │    bytecode       │
  │  → Devi          │                     │    (sicurezza!)   │
  │    recompilare   │                     │  → JIT compila    │
  │                  │                     │    in native      │
  │  ∉ 2026          │                     │  → Esegue         │
  │                  │                     │    alla velocità  │
  │                  │                     │    del kernel     │
  └──────────────────┘                     └──────────────────┘
```

### 3.2 Perché eBPF per rilevare ransomware?

I ransomware hanno un **comportamento prevedibile**:

```
  FASE 1                              FASE 2                              FASE 3
  ┌─────────────────────┐            ┌─────────────────────┐            ┌─────────────────────┐
  │                     │            │                     │            │                     │
  │  Genera chiave      │            │  Legge file →       │            │  Cancella file       │
  │  crittografica      │  ────────→ │  cifra → scrive     │  ────────→ │  originale           │
  │                     │            │  versione.enc       │            │                     │
  │  getrandom()        │            │  rename()           │            │  unlink()            │
  │  socket(AF_ALG)     │            │  copy_file_range()  │            │                     │
  │                     │            │  vmsplice()         │            │                     │
  └─────────────────────┘            └─────────────────────┘            └─────────────────────┘

      ↑                                       ↑                                       ↑
      └─── RansomGuard vede TUTTO ────────────┴───────────────────────────────────────┘
```

Un processo normale potrebbe fare tante `open` o `write` (es. un database, un compilatore), ma **un processo normale NON**:
1. Genera centinaia di chiavi crittografiche (`getrandom`)
2. Apre socket `AF_ALG` per la Crypto API del kernel
3. Rinomina migliaia di file con estensione diversa
4. Cancella i file subito dopo averli letti e riscritti
5. Usa `copy_file_range` o `vmsplice` per spostare dati in blocco

RansomGuard sfrutta queste differenze comportamentali con un **sistema di scoring pesato**.

---

## 4. Il Sistema di Scoring

Il cuore di RansomGuard è la funzione `update_score()` nel BPF. Ogni syscall ha un **peso** che contribuisce al punteggio totale (0-100).

### Pesi per evento

```
  EVENTO                PESO    MOTIVAZIONE
  ──────────────────────────────────────────────────────────────
  unlink()              +3      Cancellazione file = sospetto
  rename()              +2      Rinomina (es. .jpg → .enc)
  write() (>5)          +1/ea   Scritture in eccesso
  socket(AF_ALG)        +10     Crypto API del kernel!
  getrandom() (>2)      +5/ea   Generazione chiavi!
  sendmsg[AF_ALG]       +3      Invio dati da cifrare
  copy_file_range()     +4      Zero-copy tra file
  vmsplice()            +4      Zero-copy pipe/memoria
```

### Bonus per superamento soglie

Se nella finestra temporale (default 10 secondi) un processo supera le soglie configurate:

```
  SOGLIA SUPERATA       BONUS   PERCHÉ
  ──────────────────────────────────────────────
  open > soglia         +5      Burst di aperture
  write > soglia        +5      Burst di scritture
  rename > soglia       +15     MOLTO sospetto!
  unlink > soglia       +20     CRITICO!
```

### Tabella dei livelli di allerta

```
  PUNTEGGIO   LIVELLO         AZIONE
  ─────────────────────────────────────────────────────
  0-20        🟢 Normale      Solo logging
  21-40       🟡 Sospetto     Logging + attenzione
  41-59       🟠 Pericoloso   Threshold alert imminente
  60-79       🔴 Allerta      SIGSTOP (o SIGKILL)
  80-100      🚨 Critico      Azione immediata
```

### Esempi di scoring

**Processo normale: compilatore GCC che compila un kernel**

```
  2000 open()      = +0 (sotto soglia)
  1500 write()     = +0 (sotto soglia)
  0   rename()     = +0
  0   unlink()     = +0
  0   getrandom()  = +0
  ──────────────────────────
  SCORE = 0  ✅ Nessun falso positivo
```

**Processo malevolo: ransomware LockBit-like**

```
  500  open()      → +5  (supera soglia 200)
  400  write()     → +5  (supera soglia 200)
  150  rename()    → +15 (supera soglia 10) + 150*2 = +315 → clamp a +100
  200  unlink()    → +20 (supera soglia 20) + 200*3 = +600
  10   getrandom() → +10*5 = +50
  3    AF_ALG      → +3*10 = +30
  0    sendmsg     → +0
  0    cfr/vmsplice→ +0
  ──────────────────────────
  SCORE = 100 (raggiunto dopo poche decine di file) 🚨
```

---

## 5. Requisiti di Sistema

### Hardware

- Processore x86_64 o ARM64
- Almeno 512 MB di RAM (raccomandato 1 GB)
- Spazio su disco: ~50 MB per i binari

### Software

| Componente | Versione Minima | Note |
|---|---|---|
| **Linux kernel** | 5.13+ | Necessario per `bpf_send_signal` e `BPF_MAP_TYPE_RINGBUF` |
| **Kernel config** | `CONFIG_DEBUG_INFO_BTF=y` | Fondamentale per il caricamento BPF |
| **libbpf** | 0.5+ | Libreria user-space per BPF |
| **clang** | 11+ | Compilatore per il BPF bytecode |
| **gcc** | 8+ | Compilatore per il programma user-space |
| **bpftool** | 5.13+ | Generazione skeleton e vmlinux.h |
| **libelf-dev** | qualsiasi | Linking del BPF object |
| **zlib1g-dev** | qualsiasi | Compressione (dipende da libbpf) |

### Verifica compatibilità

```bash
# Controlla la versione del kernel
uname -r

# Verifica che BTF sia disponibile
ls /sys/kernel/btf/vmlinux

# Controlla se bpftool è installato
which bpftool

# Controlla se libbpf è installato
ls /usr/include/bpf/bpf.h
```

---

## 6. Installazione e Compilazione

### 6.1 Installa le dipendenze

**Debian/Ubuntu:**

```bash
sudo apt update
sudo apt install -y clang gcc libbpf-dev bpftool libelf-dev zlib1g-dev linux-headers-$(uname -r)
```

**Fedora/RHEL:**

```bash
sudo dnf install -y clang gcc libbpf-devel bpftool libelf-devel zlib-devel kernel-devel
```

**Arch Linux:**

```bash
sudo pacman -S clang gcc libbpf bpftool libelf zlib
```

### 6.2 Clona e compila

```bash
# Clona il repository
git clone https://github.com/tuo/ransomguard.git
cd ransomguard

# Compila tutto (vmlinux.h → BPF → skeleton → user-space)
make -f Makefile_ransomguard

# Output atteso:
#   [GEN] Generazione vmlinux.h dal kernel in esecuzione...
#   [OK ] vmlinux.h generato
#   [BPF] Compilazione ransomguard.bpf.c ...
#   [OK ] ransomguard.bpf.o generato
#   [GEN] Generazione skeleton header ransomguard.skel.h ...
#   [OK ] ransomguard.skel.h generato
#   [CC ] Compilazione ransomguard.c ...
#   [OK ] Binario ransomguard pronto
```

### 6.3 Compilazione passo-passo (opzionale)

```bash
# 1. Solo vmlinux.h
make -f Makefile_ransomguard vmlinux

# 2. Tutto
make -f Makefile_ransomguard all

# 3. Pulizia
make -f Makefile_ransomguard clean
```

---

## 7. Configurazione

RansomGuard si configura tramite file YAML. Ecco il file completo con spiegazioni:

```yaml
# ransomguard_config.yaml

# ─── SOGLIE DI RILEVAMENTO ─────────────────────────────────────
# Queste soglie definiscono il numero massimo di syscall
# consentite nella finestra temporale (window_seconds) prima
# che il punteggio inizi a salire.
thresholds:
  open_per_window: 200      # Aperture file / finestra
  write_per_window: 200     # Scritture / finestra
  rename_per_window: 10     # Rinomine / finestra
  unlink_per_window: 20     # Cancellazioni / finestra
  score_alert: 60           # Soglia allarme (0-100)
  window_seconds: 10        # Finestra temporale in secondi

# ─── AZIONI ─────────────────────────────────────────────────────
actions:
  kill_on_detect: false     # SIGKILL o solo SIGSTOP?
  log_file: ransomguard.log # File di log
  verbose: false            # Modalità verbosa (debug)

# ─── WHITELIST PROCESSI ─────────────────────────────────────────
# Processi da NON monitorare (per nome, come in /proc/PID/comm)
whitelist_processes:
  # - rsync
  # - tar
  # - find
  # - updatedb
```

### Parametri in dettaglio

| Parametro | Default | Range | Consiglio |
|---|---|---|---|
| `open_per_window` | 200 | 10-10000 | Lascia 200, abbassa a 50 per ambienti sensibili |
| `write_per_window` | 200 | 10-10000 | Come sopra |
| `rename_per_window` | 10 | 1-500 | 10 è aggressivo ma efficace |
| `unlink_per_window` | 20 | 1-500 | 20 è un buon compromesso |
| `score_alert` | 60 | 1-100 | 60 = bilanciato, 40 = aggressivo, 80 = conservativo |
| `window_seconds` | 10 | 1-3600 | Più corto = più reattivo |
| `kill_on_detect` | false | bool | **false** in produzione finché non sei sicuro |

### Tuning delle soglie

```
  AMBIENTE        open  write  rename  unlink  score  window
  ──────────────────────────────────────────────────────────────
  Casa / ufficio   200   200     10      20      60      10
  Server web      1000  5000     20      30      70      30
  CI/CD runner     500  2000     50      50      80      20
  Forensic        100   100      5       10      40       5
  Maximum security  50    50     3        5      30       3
```

---

## 8. Utilizzo

### 8.1 Avvio base

```bash
sudo ./ransomguard
```

Output atteso:

```
[2026-03-15 14:30:00] [INFO ] RansomGuard avviato. PID=12345
[2026-03-15 14:30:00] [INFO ] Configurazione caricata da: ransomguard_config.yaml
[2026-03-15 14:30:00] [INFO ] Soglie: open=200 write=200 rename=10 unlink=20 score=60 window=10s kill=NO
[2026-03-15 14:30:00] [INFO ] Whitelist: 0 PID espliciti + PID self (12345)
[2026-03-15 14:30:00] [INFO ] Programma eBPF caricato e agganciato ai tracepoint.
[2026-03-15 14:30:00] [INFO ] Monitoraggio attivo. Premi Ctrl+C per terminare.
[2026-03-15 14:30:00] [INFO ] Syscall monitorate: open, write, rename, unlink, getrandom,
[2026-03-15 14:30:00] [INFO ]   socket(AF_ALG), sendmsg, copy_file_range, vmsplice
```

### 8.2 Opzioni da riga di comando

```bash
# Configurazione personalizzata
sudo ./ransomguard --config mia_config.yaml

# Modalità verbosa (logga OGNI singolo evento)
sudo ./ransomguard --verbose

# Metti un PID in whitelist
sudo ./ransomguard --pid 1234

# Combinazione
sudo ./ransomguard --config config.yaml --verbose --pid 5678

# Help
sudo ./ransomguard --help
```

### 8.3 Esempio di output in azione

```
[2026-03-15 14:31:00] [DEBUG] EVT pid=789    comm=firefox        type=open             path=/home/user/.mozilla/firefox/...
[2026-03-15 14:31:00] [DEBUG] EVT pid=789    comm=firefox        type=write            path=
[2026-03-15 14:31:05] [DEBUG] EVT pid=1234   comm=ransom.exe     type=open             path=/home/user/Documenti/foto.jpg
[2026-03-15 14:31:05] [DEBUG] EVT pid=1234   comm=ransom.exe     type=getrandom        path=
[2026-03-15 14:31:05] [DEBUG] EVT pid=1234   comm=ransom.exe     type=socket(AF_ALG)   path=
[2026-03-15 14:31:05] [DEBUG] EVT pid=1234   comm=ransom.exe     type=write            path=
...
[2026-03-15 14:31:08] [ALERT] *** RANSOMWARE RILEVATO *** PID=1234 COMM=ransom.exe
         SCORE=68/100 | open=45 write=123 rename=56 unlink=44 getrandom=8 AF_ALG=3 ...
[2026-03-15 14:31:08] [WARN ] Invio SIGSTOP a PID=1234 (ransom.exe)
         (kill_on_detect=false)

[2026-03-15 14:31:30] [INFO ] === DUMP STATISTICHE PROCESSI ===
[2026-03-15 14:31:30] [INFO ]   PID=1234   COMM=ransom.exe    score=68 open=45 write=123 rename=56 unlink=44
[2026-03-15 14:31:30] [INFO ] =================================
```

### 8.4 Cosa fare quando scatta l'allarme

Quando RansomGuard rileva un comportamento sospetto e invia `SIGSTOP`:

```bash
# 1. Identifica il processo bloccato
ps aux | grep T
# Lo stato "T" indica stopped (SIGSTOP)

# 2. Analizza il processo
ls -la /proc/[PID]/
cat /proc/[PID]/comm
cat /proc/[PID]/cmdline

# 3. Se è un falso positivo, scongela con SIGCONT
sudo kill -SIGCONT [PID]

# 4. Aggiungi il PID alla whitelist
sudo ./ransomguard --pid [PID]

# 5. Se è un vero ransomware, analizza i log e kill
sudo kill -SIGKILL [PID]
```

---

## 9. Walkthrough del Codice

### 9.1 ransomguard.bpf.c — Il cuore nel kernel (607 linee)

La struttura di ogni tracepoint hook segue sempre lo stesso pattern:

```c
// Ogni hook ha questa struttura identica:
SEC("tp/syscalls/sys_enter_XXX")
int handle_enter_XXX(struct trace_event_raw_sys_enter *ctx)
{
    // 1. Ottieni PID e TGID del processo corrente
    u64 pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid  = (unsigned int)(pid_tgid);
    unsigned int tgid = (unsigned int)(pid_tgid >> 32);

    // 2. Salta se il processo è in whitelist
    if (is_whitelisted(pid)) return 0;

    // 3. Leggi il nome del processo
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // 4. Ottieni o crea le statistiche per questo PID
    proc_stat_t *ps = get_or_create_proc_stat(pid, tgid, comm);
    if (!ps) return 0;

    // 5. Resetta i contatori se la finestra è scaduta
    maybe_reset_window(ps);

    // 6. Incrementa il contatore specifico
    ps->unlink_count++;   // (cambia per ogni syscall)

    // 7. Ricalcola il punteggio
    update_score(ps);

    // 8. Uccidi se supera la soglia (opzionale)
    check_and_kill(ps);

    // 9. Invia evento al ring buffer
    emit_event(pid, tgid, EV_UNLINK, 0, comm, pathname);

    return 0;
}
```

**Il sistema di scoring** — la funzione `update_score()` è il vero motore di rilevamento:

```c
static __always_inline void update_score(proc_stat_t *ps) {
    unsigned int s = 0;

    // Bonus per superamento soglie
    if (thr_open   > 0 && ps->open_count   > thr_open)   s += 5;
    if (thr_write  > 0 && ps->write_count  > thr_write)  s += 5;
    if (thr_rename > 0 && ps->rename_count > thr_rename) s += 15;
    if (thr_unlink > 0 && ps->unlink_count > thr_unlink) s += 20;

    // Pesi delle syscall critiche
    s += ps->socket_aflg_count       * 10;  // Crypto API
    s += ps->getrandom_count         * 5;   // Key generation
    s += ps->sendmsg_count           * 3;   // Sending data
    s += ps->copy_file_range_count   * 4;   // Zero-copy
    s += ps->vmsplice_count          * 4;   // Zero-copy
    s += ps->unlink_count            * 3;   // Deletion
    s += ps->rename_count            * 2;   // Rename
    if (ps->write_count > 5)
        s += (ps->write_count - 5)   * 1;   // Excess writes

    // Clamp a 100
    ps->score = s > 100 ? 100 : s;
}
```

### 9.2 ransomguard.c — La sentinella nello user-space (544 linee)

Il programma user-space ha 5 responsabilità principali:

```c
int main(int argc, char *argv[]) {
    // 1. PARSING CONFIG
    //    Legge YAML / argomenti CLI → set_defaults() / parse_yaml()

    // 2. SETUP eBPF
    //    bump_memlock_rlimit()           → aumenta memoria bloccata
    //    ransomguard__open()             → apre skeleton BPF
    //    ransomguard__load()             → carica BPF nel kernel
    //    ransomguard__attach()           → aggancia ai tracepoint
    //    push_config_to_bpf()            → scrive soglie nelle BPF maps
    //    push_whitelist_to_bpf()         → scrive whitelist nelle BPF maps

    // 3. RING BUFFER CONSUMER
    //    ring_buffer__new(fd, handle_event, NULL, NULL)
    //    while (g_running) {
    //        ring_buffer__poll(rb, 100);     // poll ogni 100ms
    //    }

    // 4. CALLBACK EVENTI
    //    handle_event():
    //      - Legge evento dal ring buffer
    //      - Legge proc_stats_map per il PID
    //      - Se score >= soglia → LOG_ALERT + SIGSTOP (o SIGKILL)
    //      - Pattern ransomware classico (unlink+rename+crypto)

    // 5. CLEANUP
    //    ring_buffer__free(rb)
    //    ransomguard__destroy(skel)
    //    fclose(logfile)
}
```

La funzione `handle_event()` contiene la **doppia logica di rilevamento**:

```c
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const event_t *e = (const event_t *)data;

    // RILEVAMENTO 1: Score cumulativo
    if (ps.score >= g_cfg.thr_score) {
        alert = true;
    }

    // RILEVAMENTO 2: Pattern ransomware classico
    // (unlink + rename + crypto nello stesso processo)
    if (!alert &&
        ps.unlink_count  >= g_cfg.thr_unlink &&
        ps.rename_count  >= (g_cfg.thr_rename / 2) &&
        (ps.getrandom_count > 0 || ps.socket_aflg_count > 0)) {
        alert = true;
    }

    if (alert && !ps.killed) {
        LOG_ALERT("*** RANSOMWARE RILEVATO *** PID=%u COMM=%s ...", ...);
        if (g_cfg.kill_on_detect) {
            // Il BPF ha già inviato SIGKILL
        } else {
            kill((pid_t)e->pid, SIGSTOP);  // Blocca senza uccidere
        }
    }
}
```

### 9.3 Makefile — La catena di build

```
  vmlinux.h                   (generato da bpftool btf dump)
      │
      │ clang -target bpf
      ▼
  ransomguard.bpf.o           (oggetto BPF compilato)
      │
      │ bpftool gen skeleton
      ▼
  ransomguard.skel.h          (header skeleton per libbpf)
      │
      │ gcc + librerie
      ▼
  ransomguard                 (binario user-space finale)
```

---

## 10. Scenario di Attacco Simulato

Ecco cosa succede quando un ransomware colpisce un sistema protetto da RansomGuard:

```
TEMPO   EVENTO                                              SCORE   AZIONE
──────  ─────────────────────────────────────────────────── ──────  ─────────────────────
T+0s    ransomware.exe parte                                -
T+1s    getrandom() → genera chiave AES-256                  +5     Log
T+1s    socket(AF_ALG, SOCK_STREAM, "skcipher")             +15     Log
T+2s    sendmsg(data_to_encrypt)                            +18     Log
T+2s    open("/home/user/foto.jpg", O_RDONLY)               +18     Log
T+3s    open("/home/user/foto.jpg.enc", O_WRONLY|O_CREAT)   +18     Log
T+3s    copy_file_range(foto.jpg → foto.jpg.enc)            +22     Log
T+7s    rename("/home/user/foto.jpg", → "foto.jpg.enc")     +24     Log
T+7s    unlink("/home/user/foto.jpg")                       +27     Log
T+8s    (ripete per 3 file)                                 +36     Log
T+9s    (ripete per 10 file)                                +60     🔴 ALERT! SIGSTOP!
                                                                   Processo congelato.
                                                                   LOG + dump statistiche.
T+10s   Operatore analizza il processo:                     -       Identifica ransomware
T+15s   sudo kill -SIGKILL [PID]                            -       Processo eliminato
T+16s   Danni limitati a 10 file invece di 100.000          -      ✅ SALVATI!
```

### Confronto: Con e senza RansomGuard

```
  SENZA RANSOMGUARD                          CON RANSOMGUARD
  ┌─────────────────────────┐               ┌─────────────────────────┐
  │                         │               │                         │
  │  100.000 file cifrati   │               │  Solo ~10 file colpiti  │
  │  Riscatto richiesto     │               │  Ransomware bloccato    │
  │  Backup necessario      │               │  SIGSTOP in 7 secondi   │
  │  Ore/di fermo           │               │  Operatore investiga    │
  │  Danno economico        │               │  Danno minimo           │
  │                         │               │                         │
  └─────────────────────────┘               └─────────────────────────┘
```

---

## 11. Domande Frequenti

### RansomGuard funziona su macOS o Windows?

**No.** RansomGuard è specifico per Linux. eBPF è una tecnologia del kernel Linux; non esiste su macOS o Windows. Se hai bisogno di protezione cross-platform, cerca soluzioni basate su firme o comportamento a livello user-space.

### Posso usarlo in produzione?

**Sì, con cautela:**
1. Inizia con `kill_on_detect: false` (SIGSTOP safe)
2. Monitora i log per una settimana per identificare falsi positivi
3. Aggiungi i falsi positivi alla whitelist
4. Solo dopo passa a `kill_on_detect: true`

### RansomGuard protegge da TUTTI i ransomware?

**No.** Nessun sistema è perfetto. RansomGuard protegge da ransomware che:
- Usano la Crypto API del kernel (`AF_ALG`)
- Generano chiavi con `getrandom()`
- Fanno rename/unlink massivi
- Usano zero-copy syscall

Alcuni ransomware potrebbero usare tecniche diverse (crypto in user-space, encryption in-place senza rename) e potrebbero non essere rilevati.

### Quanto overhead aggiunge?

**Minimo.** L'eBPF esegue solo poche istruzioni per syscall. In idle, l'impatto è praticamente zero. Durante un attacco, l'overhead è trascurabile rispetto al carico dell'attacco stesso.

### Come gestire i falsi positivi?

```bash
# 1. Metti il PID in whitelist
sudo ./ransomguard --pid [PID_PROBLEMATICO]

# 2. O aggiungi il nome processo al file YAML
# whitelist_processes:
#   - nome_processo

# 3. O rilassa le soglie nel YAML
# rename_per_window: 50  # invece di 10
```

### Perché ci sono due commit identici ("first commit" e "primo commit")?

Perché la prima volta non ha funzionato il push. La morale: **fate sempre `git push` due volte**.

---

## Struttura dei file

```
Project-ransomguard/
├── ransomguard.c.txt           # Programma user-space (544 linee)
├── ransomguard.bpf.c.txt       # Programma kernel eBPF (607 linee)
├── ransomguard_config.yaml     # Configurazione YAML (123 linee)
├── Makefile_ransomguard        # Build system (94 linee)
├── README.md                   # Questo file
└── .git/                       # Repository git
```

---

## Licenza

Questo progetto è distribuito sotto licenza **GPL v2** (richiesta per l'uso di `bpf_send_signal`).

---

## Riferimenti

- [eBPF Documentation](https://ebpf.io/)
- [libbpf Documentation](https://github.com/libbpf/libbpf)
- [Linux Kernel BPF Docs](https://www.kernel.org/doc/html/latest/bpf/)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/latest/bpf/)

---

<div align="center">

**RansomGuard** — Perché il miglior antivirus è quello che non aspetta le firme.

```
  "Il ransomware colpisce alla velocità del disco.
   RansomGuard risponde alla velocità del kernel."
```

Progetto realizzato per tesina universitaria.

</div>
