# Dynamic Firewall for DDoS Detection & Mitigation

> Software-Defined Networking (SDN) based dynamic firewall research project for detecting and mitigating abnormal network traffic.

## Project Overview

This project implements an adaptive firewall as a **Ryu SDN application using OpenFlow 1.3**.

The supplied firewall source maintains per-source packet statistics, applies configurable traffic thresholds, updates dynamic thresholds periodically, detects several traffic patterns, and installs an OpenFlow rule to block a suspicious source IP.

The implementation currently contains detection branches for:

- DDoS Attack
- SYN Flood
- Port Scanning
- ICMP Flood
- UDP Flood

## Experimental Topology

The portfolio experiment uses one OpenFlow switch and four hosts:

```text
                    Ryu Controller
                         |
                    OpenFlow 1.3
                         |
                         v
                       +----+
                       | s1 |
                       +--+-+
              +----------+----------+----------+
              |          |          |          |
              v          v          v          v
             h1         h2         h3         h4
           Server      SYN         UDP       Normal
           Target     Flood       Flood      Traffic
```

| Node | Role | IP |
|---|---|---|
| h1 | Server / target | 10.0.0.1 |
| h2 | SYN Flood attacker | 10.0.0.2 |
| h3 | UDP Flood attacker | 10.0.0.3 |
| h4 | Normal traffic host | 10.0.0.4 |
| s1 | OpenFlow 1.3 switch | — |
| c0 | Ryu controller | 127.0.0.1:6633 |

## Technology Stack

- Python
- Ryu Controller
- OpenFlow 1.3
- Mininet
- Open vSwitch
- Ubuntu / Linux
- hping3
- tcpdump
- Wireshark

## Firewall Logic

The application maintains packet statistics per source IP using a configurable time window.

The supplied implementation starts with these base thresholds:

| Detection | Base Threshold |
|---|---:|
| DDoS | 1000 |
| SYN | 100 |
| SCAN | 20 |
| ICMP | 50 |
| UDP | 500 |

Thresholds are updated every 30 seconds from observed traffic statistics.

When a source exceeds the applicable threshold, the application sends an OpenFlow flow modification matching the source IPv4 address with no forwarding action, causing subsequent packets from that source to be dropped.

## Running the Experiment

### 1. Start Ryu

From the Ryu environment:

```bash
ryu-manager src/adaptive_firewall.py
```

### 2. Start Mininet

In another terminal:

```bash
sudo python3 mininet/topology.py
```

### 3. Verify topology

Inside Mininet:

```text
nodes
net
pingall
```

### 4. Start normal HTTP service

On `h1`:

```bash
python3 -m http.server 80
```

From `h4`:

```bash
curl http://10.0.0.1
```

### 5. Generate SYN Flood traffic

Use the attack command from the actual experiment environment. Do not change the command or parameters when documenting a measured result.

Example structure:

```bash
h2 hping3 -S <target> -p <port> --flood
```

### 6. Generate UDP Flood traffic

Example structure:

```bash
h3 hping3 --udp <target> -p <port> --flood
```

### 7. Capture traffic

Example:

```bash
tcpdump -i <interface> -w traffic.pcap
```

Analyze the capture with Wireshark.

## Evidence

The repository is designed to store:

- Mininet topology
- Ryu detection logs
- hping3 attack simulation
- Wireshark SYN analysis
- Wireshark UDP analysis
- Firewall blocking logs
- Normal traffic verification
- Before/after packet-count results

Place final screenshots in `docs/`.

## Experimental Results

Based on the supplied experiment evidence:

| Attack | Before | After | Packet-count reduction |
|---|---:|---:|---:|
| SYN Flood | 83,440 | 212 | 99.75% |
| UDP Flood | 404,912 | 100 | 99.98% |

These percentages describe **packet-count reduction** between the supplied before/after measurements. They should not be interpreted as a direct percentage of blocked packets unless the research methodology defines it that way.

### Normal Traffic Impact

The supplied latency result shows:

```text
Before Firewall: 1.0 ms
After Firewall : 2.5 ms
Change         : +1.5 ms
```

Detection time is intentionally not claimed here because a synchronized attack-start timestamp and first Ryu-detection timestamp were not included in the supplied evidence.

## Analysis

The project evaluates the firewall using:

1. Attack detection
2. Dynamic blocking
3. Packet-count comparison
4. Normal traffic verification
5. Packet-level traffic analysis

## Project Evidence

See the `docs/` directory for experiment screenshots and the `results/` directories for exported analysis data.

## Research Publication

**DDoS Attack Detection and Mitigation with Dynamic Firewall Technique**

IJICOM, 2025.

## Author

**Rizki Berkah Saputra**

Cyber Security & Network Security Enthusiast

GitHub: https://github.com/IAmRizki
LinkedIn: https://www.linkedin.com/in/rizki-berkah-saputra-25b879216/


## Evidence Gallery

### Experimental Topology

![Mininet topology](docs/02-mininet-topology.png)

### SYN Flood Simulation

![SYN Flood](docs/06-syn-flood-hping3.png)

### UDP Flood Simulation

![UDP Flood](docs/07-udp-flood-hping3.png)

### Traffic Analysis

![Wireshark SYN](docs/08-wireshark-syn.png)

![Wireshark UDP](docs/09-wireshark-udp.png)

### Ryu Detection and Mitigation

![Ryu detection](docs/12-ryu-detection-detail.png)

![Firewall blocked](docs/11-firewall-blocked.png)

### Normal Traffic Verification

![Normal ping](docs/13-normal-ping-detail.png)

![HTTP service](docs/10-wireshark-http.png)

### Before vs After

![Before and after](docs/01-results-before-after.png)

| Attack | Before | After | Packet-count reduction |
|---|---:|---:|---:|
| SYN Flood | 83,440 | 212 | 99.75% |
| UDP Flood | 404,912 | 100 | 99.98% |

> These percentages describe packet-count reduction between the supplied measurements. They are not presented as a direct blocked-packet percentage.

## Normal Traffic Impact

The supplied latency result is **1.0 ms before** and **2.5 ms after**, a **+1.5 ms** change.

## Detection Time

A numerical detection-time claim is intentionally omitted because the supplied evidence does not provide synchronized attack-start and first-detection timestamps.

## Repository Structure

```text
dynamic-firewall-ddos-sdn/
├── README.md
├── LICENSE
├── requirements.txt
├── src/
│   └── adaptive_firewall.py
├── mininet/
│   └── topology.py
├── analysis/
├── docs/
└── results/
```
