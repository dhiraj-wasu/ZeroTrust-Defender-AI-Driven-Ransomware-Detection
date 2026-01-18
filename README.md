🛡️ ZeroTrust Defender
AI-Driven Ransomware Detection & Central Intelligence System

ZeroTrust Defender is a distributed, AI-powered ransomware protection platform that combines real-time endpoint monitoring, multi-layer threat detection, and centralized threat intelligence orchestration to detect, contain, and respond to ransomware attacks automatically—without human intervention.

This project simulates an enterprise-grade EDR + SOAR security architecture, designed for real-time demonstrations and research-oriented security engineering.

🚀 Key Capabilities

Real-Time Endpoint Monitoring

Filesystem entropy analysis

Process behavior & CPU spike detection

Network activity & lateral movement indicators

Multi-Layer AI Detection Engine

Supervised ML detection for known ransomware

Unsupervised anomaly detection for zero-day threats

Rule-based heuristics for encryption patterns

Slow ransomware & stealth attack detection

Automated Local Containment

Emergency backup of critical directories

File locking and permission hardening

Network isolation & zero-trust enforcement

Malicious process termination

Centralized Threat Intelligence System

Correlates incidents across multiple agents

LLM-assisted ransomware classification

Network-wide containment orchestration

Forensic timeline and incident tracking

Enterprise-Style Architecture

Agent-based distributed design

Command-and-control coordination

Incident-driven response workflows

🧠 System Architecture
[ Endpoint Agents ]
  ├─ File System Monitor
  ├─ Process Analyzer
  ├─ Network Telemetry
  ├─ Local AI Detection
  └─ Auto-Containment
        │
        ▼
[ Central Intelligence System ]
  ├─ Incident Correlation
  ├─ LLM-Assisted Threat Analysis
  ├─ Response Orchestration
  └─ Network-Wide Commands

🔄 High-Level Workflow
Start Agent
   ↓
User selects critical directory
   ↓
Continuous real-time monitoring
   ↓
Multi-layer AI detection
   ↓
If ransomware detected:
   • Backup critical files
   • Lock files & isolate network
   • Enable zero-trust mode
   • Send forensic alert to central system
   ↓
Central system correlates incidents
   ↓
Network-wide containment commands issued

📂 Repository Structure
.
├── central_system/
│   ├── coordination_engine/
│   ├── forensic_correlator/
│   ├── llm_intelligence/
│   ├── agent_manager/
│   └── websocket_manager/
│
├── agent/
│   ├── monitor/
│   │   ├── file_monitor.py
│   │   ├── process_monitor.py
│   │   └── network_monitor.py
│   ├── detection/
│   │   ├── supervised_detector.py
│   │   ├── anomaly_detector.py
│   │   ├── slow_ransomware_detector.py
│   │   └── ensemble_detector.py
│   ├── prevention/
│   │   ├── backup.py
│   │   ├── file_lock.py
│   │   ├── network_isolation.py
│   │   └── process_control.py
│   └── zero_trust/
│       └── enforcer.py
│
└── docs/

🧪 Demo Capabilities

Monitor user-defined critical folders

Simulate ransomware encryption behavior

Observe real-time detection & containment

View centralized incident correlation

Execute network-wide response commands

Designed specifically to showcase real security behavior during demos, not mock outputs.

🎯 Skills Demonstrated

Distributed Systems Design

Real-Time Security Monitoring

AI-Based Threat Detection

Incident Response Automation

Zero-Trust Architecture

Threat Intelligence Correlation

Enterprise Security Engineering

📈 Why This Project Matters

This is not a basic malware scanner.

It demonstrates:

How modern enterprises detect ransomware

How endpoints act autonomously

How intelligence is centralized and reused

How attacks are contained at network scale

Equivalent to a mini EDR + SOAR platform built from scratch.

🔮 Future Enhancements

Deep learning-based ransomware classifiers

SIEM & SOC platform integration

Containerized deployment (Docker/Kubernetes)

Multi-node central system clustering

Cloud threat-intelligence feeds

👤 Author

Dhiraj Vinod Wasu
Computer Science Engineer | Backend & Systems Enthusiast
📧 2023bcs510@sggs.ac.in

⭐ If you find this project interesting, feel free to star the repository!
