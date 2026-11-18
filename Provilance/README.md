# Provilance Enterprise Intelligence Platform

Provilance is a unified, self-contained search and analytics platform built by bundling an enterprise search engine (Elasticsearch core) with an interactive web dashboard (Kibana core), packaged into native Windows executables.

---

## 🚀 Key Files in this Package

| File | Purpose |
| :--- | :--- |
| **`ProvilanceSetup.exe`** | **The Windows Installer**. Run this on any machine to install Provilance (Select directory, auto-creates Desktop & Start Menu shortcuts, and launches Provilance). |
| **`Provilance.exe`** | **The Main App Launcher**. Starts the search engine & dashboard in the background (hidden without CMD popups), waits for the web server, and automatically opens your browser to `http://localhost:5601` (just like Splunk). |
| **`Stop-Provilance.exe`** | **The Service Stopper**. Terminates all background Provilance services cleanly. |
| **`assets/provilance.ico`** | The custom branded Provilance icon embedded into all binaries. |
| **`src/`** | C# source code for the launcher, stopper, installer, and compiler response files (`.rsp`). |

---

## 🖥️ How It Works (Splunk-like Experience)

1. **Running Directly**:
   * Double-click `Provilance.exe`.
   * Provilance appears in your Windows **System Tray** (near the clock).
   * It starts the engine and dashboard in the background.
   * As soon as the service is ready, your browser automatically opens to `http://localhost:5601`.

2. **Installing via Setup Wizard**:
   * Double-click `ProvilanceSetup.exe`.
   * Choose your install location (Default: `C:\Provilance`).
   * Click **Install**.
   * Desktop shortcut **"Provilance"** will be created with its custom icon.
   * Click **Finish** to immediately launch the platform.

3. **Managing via System Tray**:
   * Right-click the Provilance icon in the taskbar notification area:
     * **Open Provilance Web**: Re-opens `http://localhost:5601`.
     * **Restart Services**: Restarts backend engine and dashboard.
     * **Stop & Exit**: Gracefully stops all processes.
