# ⚠️ Network Threat Finder

This tool helps you **scan and identify active remote connections** on your system that may be associated with **malicious processes or viruses**, using `netstat`, `PowerShell`, and **VirusTotal API**.  
> ⚠️ **Note:** This application only identifies suspicious activity — it does **not remove viruses or kill processes**. Manual action is required if threats are found.

---

## 🚀 Features

- Identify remote connections using `netstat`
- Cross-reference IPs with [VirusTotal](https://www.virustotal.com/)
- Display process name and executable path
- Filter out local and safe connections
- Warn about connections flagged as malicious

---

## 🛠 Installation

1. **Install Node.js** (if you haven’t already):  
   👉 [https://nodejs.org/](https://nodejs.org/)

2. **Download or clone this repository.**

3. Open a terminal in the project folder and run:

   ```bash
   npm install
   ```

4. To start scanning your network:

   ```bash
   node .
   ```

---

## 📸 Example Output

```
⚠️ Malicious IP detected: 185.234.219.25
┌───────────────┬──────────────────────────────────────────────────────┐
│  Protocol     │ TCP                                                  │
│  Local Addr   │ 192.168.1.10:49502                                    │
│  Remote Addr  │ 185.234.219.25:443                                    │
│  PID          │ 6345                                                 │
│  Process Name │ chrome.exe                                           │
│  Path         │ C:\Program Files\Google\Chrome\Application\chrome.exe│
│  VirusTotal   │ Malicious: 3, Suspicious: 1                          │
└───────────────┴──────────────────────────────────────────────────────┘
```

---

## 📌 Notes

- You’ll need a **VirusTotal API Key** to enable online threat detection.
- Keep in mind: API keys for free accounts are limited to 4 requests/minute and 500/day.
- Do **not** share your key publicly.

---

## 👤 Author

Created by **erutluZ - Last Project VV**  
Feel free to contribute or report issues!