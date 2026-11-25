# SecTriage

A lightweight security triage utility built in Python and Streamlit for static URL phishing heuristic scoring and SSH authentication log brute-force detection.

## Features
- **URL Inspector:** Evaluates scheme security, raw IP hosts, `@` credential-obscuring syntax, Punycode homographs, subdomain depth, high-abuse TLDs, and phishing keywords.
- **Auth Log Triage:** Parses `sshd` authentication logs to aggregate failed login attempts by source IP and targeted username against a configurable threshold.

## Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py