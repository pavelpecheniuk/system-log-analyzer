# LogInsight: A Scalable, Multiformat Log Analysis Framework for System Anomalies Detection
A lightweight, scalable, multiformat log analyser performing anomaly detection and alerting about anomalies.

# Overview
LogInsight is a log analysis tool written in Python that is designed to: extract raw log data from the diverse log sources (Linux-based plaintext logs, JSON-formatted Windows-based logs, generic CSV log files), transform it into the ordered log statements and detect anomalies in real time to gain security-relevant insights into the
system activity. This is a baseline tool that serves both as lightweight analysing framework and foundation for further, more advanced intelligent framework.

# Key Features
1. Log Parser
- Supports plaintext, JSON, and CSV log formats.
- Parsing rules are set and fetched from the YAML configuration file — no code modification required.
2. Point Anomaly Detection
- Template anomalies are detected using regex-based patterns (failed login attempts, failed connections, kernel panics...).
- Attribute anomalies are detected using Interquartile Range (IQR) statistics to capture deviant behavior of numeric values in the log fields (high CPU usage, unexpected duration values, different out-of-range values).
3. Contextual Anomaly Detection
- The unsupervised technique N-gram sequence modeling is used to identify abnormally ordered event happenings via learning from normal event patterns.
- Detects deviations in operational workflow (abnormal login sequences).
- Anomaly rules for both methods are stored similarly in the dedicated config file.
4. Alerting System
Instant reporting in real time via console alerts and SMTP-assisted email alerts.

# Notes for Usage
- Paths to locations of config files and logs are hardcoded, so keep an eye for it.

# License
MIT License – free to use and extend.
