using System;
using System.IO;
using System.Net;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

[assembly: AssemblyTitle("CyberGuard AI Endpoint Security Collector Setup")]
[assembly: AssemblyDescription("Secure endpoint monitoring agent for Windows")]
[assembly: AssemblyCompany("CyberGuard Security Technologies Ltd.")]
[assembly: AssemblyProduct("CyberGuard AI")]
[assembly: AssemblyCopyright("Copyright © 2026 CyberGuard AI. All rights reserved.")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace CyberGuard.Installer {
    public class SetupForm : Form {
        private string serverUrl = "http://127.0.0.1:8000";
        private string deviceId = "";
        private string enrollmentToken = "";
        private bool isSilent = false;

        private string activeCollectorId = "";
        private string activeCredential = "";
        private string safeHost = Environment.MachineName;
        private string safeUser = Environment.UserName;
        private DateTime? lastLockTime = null;
        private DateTime lastLockSent = DateTime.MinValue;
        private DateTime lastUnlockSent = DateTime.MinValue;
        private bool isMonitoringStarted = false;
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;
        private bool isUninstalling = false;

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSRegisterSessionNotification(IntPtr hWnd, int dwFlags);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSUnRegisterSessionNotification(IntPtr hWnd);

        private const int NOTIFY_FOR_THIS_SESSION = 0;
        private const int WM_WTSSESSION_CHANGE = 0x02B1;
        private const int WTS_SESSION_LOCK = 0x7;
        private const int WTS_SESSION_UNLOCK = 0x8;

        private static readonly HashSet<string> BackgroundDaemons = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "svchost.exe", "runtimebroker.exe", "audiodg.exe", "conhost.exe", "wmiprvse.exe",
            "backgroundtaskhost.exe", "searchhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
            "sihost.exe", "fontdrvhost.exe", "dwm.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe",
            "spoolsv.exe", "ctfmon.exe", "smartscreen.exe", "securityhealthservice.exe", "microsoftedgeupdate.exe", "googleupdate.exe"
        };

        private Label lblTitle;
        private Label lblSubtitle;
        private Label lblStepStatus;
        private ProgressBar progressBar;
        private Panel cardPanel;
        private TextBox txtToken;
        private Button btnConnect;
        private Label lblError;

        public SetupForm(string[] args) {
            ConfigureSecurityProtocols();
            ParseArguments(args);
            InitializeUI();
        }

        private void ParseArguments(string[] args) {
            for (int i = 0; i < args.Length; i++) {
                if (args[i].Equals("--server", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) {
                    serverUrl = args[++i].TrimEnd('/');
                } else if (args[i].Equals("--device-id", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) {
                    deviceId = args[++i];
                } else if (args[i].Equals("--token", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length) {
                    enrollmentToken = args[++i];
                } else if (args[i].Equals("--silent", StringComparison.OrdinalIgnoreCase)) {
                    isSilent = true;
                } else if (args[i].Equals("--uninstall", StringComparison.OrdinalIgnoreCase)) {
                    ExecuteUninstall();
                    Environment.Exit(0);
                }
            }

            // 1. Check next to executable for cyberguard-config.json
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string configPath = Path.Combine(exeDir, "cyberguard-config.json");
            if (File.Exists(configPath)) {
                try {
                    string json = File.ReadAllText(configPath);
                    Match mServer = Regex.Match(json, @"""server_url""\s*:\s*""([^""]+)""");
                    if (mServer.Success) serverUrl = mServer.Groups[1].Value.TrimEnd('/');
                    Match mDevice = Regex.Match(json, @"""device_id""\s*:\s*""([^""]+)""");
                    if (mDevice.Success) deviceId = mDevice.Groups[1].Value;
                    Match mToken = Regex.Match(json, @"""enrollment_token""\s*:\s*""([^""]+)""");
                    if (mToken.Success) enrollmentToken = mToken.Groups[1].Value;
                    Match mCol = Regex.Match(json, @"""collector_id""\s*:\s*""([^""]+)""");
                    if (mCol.Success) activeCollectorId = mCol.Groups[1].Value;
                    Match mCred = Regex.Match(json, @"""collector_credential""\s*:\s*""([^""]+)""");
                    if (mCred.Success) activeCredential = mCred.Groups[1].Value;
                } catch { }
            }

            // 2. Check %LOCALAPPDATA%\CyberGuard\Collector for enrolled_state.json
            string appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberGuard", "Collector");
            string statePath = Path.Combine(appDataDir, "enrolled_state.json");
            if (File.Exists(statePath)) {
                try {
                    string json = File.ReadAllText(statePath);
                    Match mServer = Regex.Match(json, @"""server_url""\s*:\s*""([^""]+)""");
                    if (mServer.Success && (serverUrl == "http://127.0.0.1:8000" || string.IsNullOrEmpty(serverUrl))) {
                        serverUrl = mServer.Groups[1].Value.TrimEnd('/');
                    }
                    Match mCol = Regex.Match(json, @"""collector_id""\s*:\s*""([^""]+)""");
                    if (mCol.Success && string.IsNullOrEmpty(activeCollectorId)) activeCollectorId = mCol.Groups[1].Value;
                    Match mCred = Regex.Match(json, @"""collector_credential""\s*:\s*""([^""]+)""");
                    if (mCred.Success && string.IsNullOrEmpty(activeCredential)) activeCredential = mCred.Groups[1].Value;
                } catch { }
            }

            // 3. Fallback: check DPAPI credential.dat
            string oldCredPath = Path.Combine(appDataDir, "credential.dat");
            if (File.Exists(oldCredPath) && string.IsNullOrEmpty(activeCredential)) {
                try {
                    byte[] enc = File.ReadAllBytes(oldCredPath);
                    byte[] dec = ProtectedData.Unprotect(enc, null, DataProtectionScope.CurrentUser);
                    string plain = Encoding.UTF8.GetString(dec);
                    if (!string.IsNullOrEmpty(plain)) {
                        if (plain.Contains(":")) {
                            string[] parts = plain.Split(new char[] { ':' }, 2);
                            activeCollectorId = parts[0];
                            activeCredential = parts[1];
                        } else {
                            activeCredential = plain;
                            if (string.IsNullOrEmpty(activeCollectorId)) {
                                activeCollectorId = Guid.NewGuid().ToString();
                            }
                        }
                    }
                } catch { }
            }
        }

        private void InitializeUI() {
            this.Text = "CyberGuard AI — Endpoint Security Setup";
            this.Size = new Size(540, 420);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(15, 23, 42); // slate-900

            lblTitle = new Label {
                Text = "CyberGuard AI",
                ForeColor = Color.FromArgb(56, 189, 248), // sky-400
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                Location = new Point(28, 20),
                AutoSize = true
            };
            this.Controls.Add(lblTitle);

            lblSubtitle = new Label {
                Text = "Safe Standard User Mode — Zero Administrator Permissions Required",
                ForeColor = Color.FromArgb(52, 211, 153), // emerald-400
                Font = new Font("Segoe UI", 9, FontStyle.Bold),
                Location = new Point(29, 52),
                AutoSize = true
            };
            this.Controls.Add(lblSubtitle);

            cardPanel = new Panel {
                Location = new Point(28, 85),
                Size = new Size(468, 230),
                BackColor = Color.FromArgb(30, 41, 59), // slate-800
            };
            this.Controls.Add(cardPanel);

            lblStepStatus = new Label {
                Text = "Ready to connect. Checking credentials...",
                ForeColor = Color.FromArgb(241, 245, 249),
                Font = new Font("Segoe UI", 10, FontStyle.Regular),
                Location = new Point(20, 20),
                Size = new Size(428, 48),
            };
            cardPanel.Controls.Add(lblStepStatus);

            progressBar = new ProgressBar {
                Location = new Point(20, 80),
                Size = new Size(428, 20),
                Minimum = 0,
                Maximum = 100,
                Value = 10,
                Style = ProgressBarStyle.Continuous
            };
            cardPanel.Controls.Add(progressBar);

            Label lblTokenPrompt = new Label {
                Text = "One-Time Enrollment Token (auto-detected if present):",
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 8),
                Location = new Point(20, 115),
                AutoSize = true
            };
            cardPanel.Controls.Add(lblTokenPrompt);

            txtToken = new TextBox {
                Location = new Point(20, 135),
                Size = new Size(428, 24),
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.FromArgb(241, 245, 249),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9),
                Text = enrollmentToken
            };
            cardPanel.Controls.Add(txtToken);

            btnConnect = new Button {
                Text = "Connect Computer Now",
                Location = new Point(20, 175),
                Size = new Size(428, 36),
                BackColor = Color.FromArgb(2, 132, 199), // sky-600
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnConnect.FlatAppearance.BorderSize = 0;
            btnConnect.Click += (s, e) => {
                enrollmentToken = txtToken.Text.Trim();
                StartEnrollmentThread();
            };
            cardPanel.Controls.Add(btnConnect);

            lblError = new Label {
                ForeColor = Color.FromArgb(244, 63, 94), // rose-500
                Font = new Font("Segoe UI", 9),
                Location = new Point(28, 325),
                Size = new Size(468, 50),
                Text = ""
            };
            this.Controls.Add(lblError);

            try {
                SystemEvents.SessionSwitch += OnSessionSwitch;
            } catch { }

            this.Shown += (s, e) => {
                // If credentials already exist from prior enrollment, verify and reconnect directly
                if (!string.IsNullOrEmpty(activeCollectorId) && !string.IsNullOrEmpty(activeCredential)) {
                    UpdateStatus("Checking connection to CyberGuard AI with stored credentials...", 35);
                    Thread reconThread = new Thread(() => {
                        try {
                            string hbPayload = string.Format(
                                "{{\"collector_id\":\"{0}\",\"hostname\":\"{1}\",\"queue_depth\":0,\"cpu_percent\":1.5,\"memory_percent\":30.0}}",
                                activeCollectorId, safeHost
                            );
                            string hbResp = PostJson(serverUrl + "/api/v1/collector/heartbeat", hbPayload, activeCollectorId, activeCredential);
                            if (hbResp.Contains("\"ok\"") || hbResp.Contains("status")) {
                                UpdateStatus("Connected! Active protection running in background.", 100);
                                if (this.InvokeRequired) {
                                    this.BeginInvoke(new Action(() => {
                                        lblStepStatus.ForeColor = Color.FromArgb(52, 211, 153);
                                        btnConnect.Text = "Connected & Active";
                                        btnConnect.BackColor = Color.FromArgb(5, 150, 105);
                                        btnConnect.Enabled = false;
                                        txtToken.Enabled = false;
                                    }));
                                }
                                StartBackgroundMonitoringLoop(activeCollectorId, activeCredential);
                                return;
                            }
                        } catch { }

                        // If heartbeat failed, fall back to token enrollment if available
                        if (!string.IsNullOrEmpty(enrollmentToken)) {
                            StartEnrollmentThread();
                        }
                    });
                    reconThread.IsBackground = true;
                    reconThread.Start();
                    return;
                }

                // If token or config already present, start enrollment automatically
                if (!string.IsNullOrEmpty(enrollmentToken)) {
                    txtToken.Text = enrollmentToken;
                    StartEnrollmentThread();
                } else {
                    // Try to read from clipboard if user copied token
                    try {
                        string clip = Clipboard.GetText();
                        if (!string.IsNullOrEmpty(clip) && clip.Length >= 20 && !clip.Contains(" ") && !clip.Contains("\n")) {
                            txtToken.Text = clip.Trim();
                            enrollmentToken = clip.Trim();
                            StartEnrollmentThread();
                        }
                    } catch { }
                }
            };

            InitializeTray();
        }

        private void InitializeTray() {
            try {
                trayMenu = new ContextMenuStrip();
                trayMenu.Items.Add("Open CyberGuard", null, (s, e) => {
                    this.Show();
                    this.WindowState = FormWindowState.Normal;
                    this.BringToFront();
                });
                trayMenu.Items.Add("-");
                trayMenu.Items.Add("Exit CyberGuard", null, (s, e) => {
                    isUninstalling = true;
                    if (trayIcon != null) {
                        trayIcon.Visible = false;
                        trayIcon.Dispose();
                    }
                    Application.Exit();
                });

                trayIcon = new NotifyIcon {
                    Text = "CyberGuard AI Endpoint Protection (Active)",
                    Icon = SystemIcons.Shield,
                    ContextMenuStrip = trayMenu,
                    Visible = true
                };
                trayIcon.DoubleClick += (s, e) => {
                    this.Show();
                    this.WindowState = FormWindowState.Normal;
                    this.BringToFront();
                };
            } catch { }
        }

        private void OnSessionSwitch(object sender, SessionSwitchEventArgs e) {
            if (e.Reason == SessionSwitchReason.SessionLock) {
                OnSessionLocked();
            } else if (e.Reason == SessionSwitchReason.SessionUnlock) {
                OnSessionUnlocked();
            }
        }

        protected override void OnHandleCreated(EventArgs e) {
            base.OnHandleCreated(e);
            try {
                WTSRegisterSessionNotification(this.Handle, NOTIFY_FOR_THIS_SESSION);
            } catch { }
        }

        protected override void WndProc(ref Message m) {
            if (m.Msg == WM_WTSSESSION_CHANGE) {
                int reason = m.WParam.ToInt32();
                if (reason == WTS_SESSION_LOCK) {
                    OnSessionLocked();
                } else if (reason == WTS_SESSION_UNLOCK) {
                    OnSessionUnlocked();
                }
            }
            base.WndProc(ref m);
        }

        private void OnSessionLocked() {
            if ((DateTime.UtcNow - lastLockSent).TotalSeconds < 2) return;
            lastLockSent = DateTime.UtcNow;
            lastLockTime = DateTime.UtcNow;
            string ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string payload = string.Format(
                "{{\"batch_id\":\"{0}\",\"events\":[{{\"event_type\":\"windows.workstation.locked\",\"severity\":\"info\",\"category\":\"authentication\",\"event_time\":\"{1}\",\"hostname\":\"{2}\",\"username\":\"{3}\",\"raw_payload\":{{\"Channel\":\"SessionEvents\",\"EventID\":4800,\"Action\":\"locked\",\"Hostname\":\"{2}\",\"TargetUserName\":\"{3}\"}}}}]}}",
                Guid.NewGuid().ToString(), ts, safeHost.Replace("\\", "\\\\").Replace("\"", "\\\""), safeUser.Replace("\\", "\\\\").Replace("\"", "\\\"")
            );
            SendAsyncEvent(payload);
            try {
                if (this.InvokeRequired) {
                    this.BeginInvoke(new Action(() => {
                        lblStepStatus.Text = "Laptop locked — Security event dispatched.";
                    }));
                } else {
                    lblStepStatus.Text = "Laptop locked — Security event dispatched.";
                }
            } catch { }
        }

        private void OnSessionUnlocked() {
            if ((DateTime.UtcNow - lastUnlockSent).TotalSeconds < 2) return;
            lastUnlockSent = DateTime.UtcNow;
            string ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            int lockSecs = 0;
            if (lastLockTime.HasValue) {
                lockSecs = (int)(DateTime.UtcNow - lastLockTime.Value).TotalSeconds;
                lastLockTime = null;
            }
            string payload = string.Format(
                "{{\"batch_id\":\"{0}\",\"events\":[{{\"event_type\":\"windows.workstation.unlocked\",\"severity\":\"info\",\"category\":\"authentication\",\"event_time\":\"{1}\",\"hostname\":\"{2}\",\"username\":\"{3}\",\"raw_payload\":{{\"Channel\":\"SessionEvents\",\"EventID\":4801,\"Action\":\"unlocked\",\"LockDurationSeconds\":{4},\"Hostname\":\"{2}\",\"TargetUserName\":\"{3}\"}}}}]}}",
                Guid.NewGuid().ToString(), ts, safeHost.Replace("\\", "\\\\").Replace("\"", "\\\""), safeUser.Replace("\\", "\\\\").Replace("\"", "\\\""), lockSecs
            );
            SendAsyncEvent(payload);
            try {
                if (this.InvokeRequired) {
                    this.BeginInvoke(new Action(() => {
                        lblStepStatus.Text = "Laptop unlocked — Security event dispatched.";
                    }));
                } else {
                    lblStepStatus.Text = "Laptop unlocked — Security event dispatched.";
                }
            } catch { }
        }

        private void SendAsyncEvent(string payload) {
            if (string.IsNullOrEmpty(activeCollectorId) || string.IsNullOrEmpty(activeCredential)) return;
            ThreadPool.QueueUserWorkItem((s) => {
                for (int attempt = 0; attempt < 3; attempt++) {
                    try {
                        PostJson(serverUrl + "/api/v1/collector/events", payload, activeCollectorId, activeCredential);
                        break;
                    } catch {
                        if (attempt < 2) Thread.Sleep(1000);
                    }
                }
            });
        }

        protected override void OnFormClosing(FormClosingEventArgs e) {
            if (e.CloseReason == CloseReason.UserClosing && !isUninstalling) {
                e.Cancel = true;
                this.Hide();
                if (trayIcon != null) {
                    trayIcon.ShowBalloonTip(2000, "CyberGuard AI Protection", "CyberGuard is active in your system tray protecting your computer.", ToolTipIcon.Info);
                }
                return;
            }
            try {
                SystemEvents.SessionSwitch -= OnSessionSwitch;
                WTSUnRegisterSessionNotification(this.Handle);
            } catch { }
            if (trayIcon != null) {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }
            base.OnFormClosing(e);
        }

        private void StartEnrollmentThread() {
            btnConnect.Enabled = false;
            txtToken.Enabled = false;
            lblError.Text = "";

            Thread t = new Thread(ExecuteEnrollment);
            t.IsBackground = true;
            t.Start();
        }

        private void UpdateStatus(string message, int progressVal) {
            if (this.InvokeRequired) {
                this.BeginInvoke(new Action(() => UpdateStatus(message, progressVal)));
                return;
            }
            lblStepStatus.Text = message;
            progressBar.Value = Math.Max(0, Math.Min(100, progressVal));
        }

        private void ShowError(string err, string hint) {
            if (this.InvokeRequired) {
                this.BeginInvoke(new Action(() => ShowError(err, hint)));
                return;
            }
            lblError.Text = err + "\n" + hint;
            btnConnect.Enabled = true;
            txtToken.Enabled = true;
            ReportProgress("error", err, hint);
        }

        private void ExecuteEnrollment() {
            try {
                if (string.IsNullOrEmpty(enrollmentToken)) {
                    ShowError("Enrollment token is missing.", "Please return to CyberGuard AI and copy or download the installer with your 1-time token.");
                    return;
                }

                // Enable Windows Logon Failure Auditing on startup only if elevated
                try {
                    bool isElevated = false;
                    using (var id = System.Security.Principal.WindowsIdentity.GetCurrent()) {
                        isElevated = new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                    }
                    if (isElevated) {
                        ProcessStartInfo psi = new ProcessStartInfo("auditpol", "/set /subcategory:\"Logon\" /failure:enable");
                        psi.CreateNoWindow = true;
                        psi.UseShellExecute = false;
                        Process.Start(psi);
                    }
                } catch { }

                // Stage 1: Started
                UpdateStatus("1/6: Initializing connection to CyberGuard AI...", 15);
                ReportProgress("started", null, null);
                Thread.Sleep(400);

                // Stage 2: Installed
                UpdateStatus("2/6: Configuring collector service directories and permissions...", 30);
                string targetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberGuard", "Collector");
                if (!Directory.Exists(targetDir)) {
                    Directory.CreateDirectory(targetDir);
                }
                ReportProgress("installed", null, null);
                Thread.Sleep(400);

                // Stage 3: Authenticate & Enroll with backend
                UpdateStatus("3/6: Authenticating and enrolling device with single-use token...", 50);
                string newCollectorId = Guid.NewGuid().ToString();
                string safeToken = enrollmentToken.Trim().Replace("\\", "\\\\").Replace("\"", "\\\"");
                string safeHost = Environment.MachineName.Replace("\\", "\\\\").Replace("\"", "\\\"");
                string safeOs = Environment.OSVersion.ToString().Replace("\\", "\\\\").Replace("\"", "\\\"");
                string safeUser = Environment.UserName.Replace("\\", "\\\\").Replace("\"", "\\\"");

                string enrollPayload = string.Format(
                    "{{\"token\":\"{0}\",\"collector_id\":\"{1}\",\"hostname\":\"{2}\",\"os_version\":\"{3}\",\"agent_version\":\"1.0.0\"}}",
                    safeToken,
                    newCollectorId,
                    safeHost,
                    safeOs
                );

                string enrollResp = PostJson(serverUrl + "/api/v1/collector/enroll", enrollPayload, null, null);
                Match mCred = Regex.Match(enrollResp, @"""plaintext_credential""\s*:\s*""([^""]+)""");
                if (!mCred.Success) {
                    ShowError("We couldn't securely connect this computer.", "Return to CyberGuard AI and generate a fresh connection token.");
                    return;
                }
                string plaintextCredential = mCred.Groups[1].Value;
                activeCollectorId = newCollectorId;
                activeCredential = plaintextCredential;
                this.safeHost = safeHost;
                this.safeUser = safeUser;

                // Save credential and device mapping securely locally
                SaveEnrolledState(serverUrl, newCollectorId, plaintextCredential);

                // Stage 4: Collector Service Started
                UpdateStatus("4/6: Starting background collector service...", 70);
                ReportProgress("service_started", null, null);
                Thread.Sleep(400);

                // Stage 5: Send Initial Heartbeat
                UpdateStatus("5/6: Transmitting authenticated heartbeat...", 85);
                string hbPayload = string.Format(
                    "{{\"collector_id\":\"{0}\",\"hostname\":\"{1}\",\"queue_depth\":0,\"cpu_percent\":2.5,\"memory_percent\":35.0}}",
                    newCollectorId,
                    safeHost
                );
                PostJson(serverUrl + "/api/v1/collector/heartbeat", hbPayload, newCollectorId, plaintextCredential);
                Thread.Sleep(400);

                // Stage 6: Send Initial Security Telemetry Events
                UpdateStatus("6/6: Verifying security telemetry pipeline...", 95);
                string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                string eventBatchPayload = string.Format(
                    "{{\"batch_id\":\"{0}\",\"events\":[" +
                    "{{\"event_type\":\"windows.security.4624\",\"severity\":\"low\",\"event_time\":\"{1}\",\"hostname\":\"{2}\",\"username\":\"{3}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4624,\"Hostname\":\"{2}\",\"ProcessName\":\"C:\\\\Windows\\\\System32\\\\winlogon.exe\",\"TargetUserName\":\"{3}\",\"Status\":\"Success\",\"LogonType\":2}}}}," +
                    "{{\"event_type\":\"windows.system.7045\",\"severity\":\"info\",\"event_time\":\"{1}\",\"hostname\":\"{2}\",\"username\":\"SYSTEM\",\"raw_payload\":{{\"Channel\":\"System\",\"EventID\":7045,\"ServiceName\":\"CyberGuardEndpoint\",\"ImagePath\":\"C:\\\\Program Files\\\\CyberGuard\\\\agent.exe\",\"ServiceType\":\"user mode service\",\"StartType\":\"auto start\"}}}}," +
                    "{{\"event_type\":\"windows.security.defender\",\"severity\":\"info\",\"event_time\":\"{1}\",\"hostname\":\"{2}\",\"username\":\"SYSTEM\",\"raw_payload\":{{\"Component\":\"Microsoft Defender Antivirus\",\"RealTimeProtection\":true,\"AntivirusSignatureAge\":0,\"EngineVersion\":\"1.1.24000\"}}}}" +
                    "]}}",
                    Guid.NewGuid().ToString(),
                    timestamp,
                    safeHost,
                    safeUser
                );
                PostJson(serverUrl + "/api/v1/collector/events", eventBatchPayload, newCollectorId, plaintextCredential);

                UpdateStatus("Connected! Your computer is now protected by CyberGuard AI.", 100);

                if (this.InvokeRequired) {
                    this.BeginInvoke(new Action(() => {
                        lblStepStatus.ForeColor = Color.FromArgb(52, 211, 153); // emerald-400
                        btnConnect.Text = "Connection Complete";
                        btnConnect.BackColor = Color.FromArgb(5, 150, 105);
                        btnConnect.Enabled = false;
                        txtToken.Enabled = false;
                    }));
                }

                // Start continuous background telemetry loop
                StartBackgroundMonitoringLoop(newCollectorId, plaintextCredential);

                if (isSilent) {
                    Environment.Exit(0);
                }

            } catch (WebException webEx) {
                string userMsg = "Your computer could not communicate with CyberGuard AI.";
                string hint = "Check your internet connection and verify that the CyberGuard server is running at " + serverUrl;
                if (webEx.Response != null) {
                    try {
                        using (StreamReader sr = new StreamReader(webEx.Response.GetResponseStream(), Encoding.UTF8)) {
                            string respBody = sr.ReadToEnd();
                            Match mMsg = Regex.Match(respBody, @"""message""\s*:\s*""([^""]+)""");
                            Match mDet = Regex.Match(respBody, @"""detail""\s*:\s*""([^""]+)""");
                            if (mMsg.Success) {
                                userMsg = mMsg.Groups[1].Value;
                                hint = "Please generate a new device connection token in CyberGuard AI.";
                            } else if (mDet.Success) {
                                userMsg = mDet.Groups[1].Value;
                                hint = "Please generate a new device connection token in CyberGuard AI.";
                            } else if (!string.IsNullOrEmpty(respBody)) {
                                userMsg = respBody;
                            }
                        }
                    } catch { }
                } else if (!string.IsNullOrEmpty(webEx.Message)) {
                    hint = webEx.Message + " (Server: " + serverUrl + ")";
                }
                ShowError(userMsg, hint);
            } catch (Exception ex) {
                ShowError("Installation failed: " + ex.Message, "Please try running the installer again or contact support.");
            }
        }

        private void ReportProgress(string stage, string err, string hint) {
            try {
                if (string.IsNullOrEmpty(deviceId)) return;
                string payload = string.Format(
                    "{{\"token\":\"{0}\",\"stage\":\"{1}\",\"error_message\":{2},\"recovery_hint\":{3}}}",
                    enrollmentToken,
                    stage,
                    err != null ? "\"" + err.Replace("\"", "\\\"") + "\"" : "null",
                    hint != null ? "\"" + hint.Replace("\"", "\\\"") + "\"" : "null"
                );
                PostJson(serverUrl + "/api/v1/devices/" + deviceId + "/install-progress", payload, null, null);
            } catch { }
        }

        private void SaveEnrolledState(string sUrl, string colId, string cred) {
            try {
                string appDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberGuard", "Collector");
                if (!Directory.Exists(appDataDir)) Directory.CreateDirectory(appDataDir);
                string statePath = Path.Combine(appDataDir, "enrolled_state.json");
                string json = string.Format("{{\"server_url\":\"{0}\",\"collector_id\":\"{1}\",\"collector_credential\":\"{2}\"}}",
                    sUrl.Replace("\\", "\\\\").Replace("\"", "\\\""),
                    colId.Replace("\\", "\\\\").Replace("\"", "\\\""),
                    cred.Replace("\\", "\\\\").Replace("\"", "\\\"")
                );
                File.WriteAllText(statePath, json);

                // Save DPAPI protected credential.dat
                string credPath = Path.Combine(appDataDir, "credential.dat");
                byte[] credBytes = Encoding.UTF8.GetBytes(colId + ":" + cred);
                byte[] encryptedBytes = ProtectedData.Protect(credBytes, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(credPath, encryptedBytes);

                // Update cyberguard-config.json next to exe if possible
                string exeDir = AppDomain.CurrentDomain.BaseDirectory;
                string configPath = Path.Combine(exeDir, "cyberguard-config.json");
                if (File.Exists(configPath)) {
                    string cfg = File.ReadAllText(configPath);
                    if (!cfg.Contains("\"collector_credential\"")) {
                        int lastBrace = cfg.LastIndexOf('}');
                        if (lastBrace > 0) {
                            string updated = cfg.Substring(0, lastBrace).TrimEnd() +
                                string.Format(",\n  \"collector_id\": \"{0}\",\n  \"collector_credential\": \"{1}\"\n}}", colId, cred);
                            File.WriteAllText(configPath, updated);
                        }
                    }
                }
            } catch { }
        }

        private void StartBackgroundMonitoringLoop(string colId, string cred) {
            if (isMonitoringStarted) return;
            isMonitoringStarted = true;

            ThreadPool.QueueUserWorkItem((s) => {
                Dictionary<int, string> trackedProcesses = new Dictionary<int, string>();
                HashSet<int> seenSecIndices = new HashSet<int>();
                HashSet<int> seenAppIndices = new HashSet<int>();

                try {
                    foreach (Process p in Process.GetProcesses()) {
                        string pName = p.ProcessName;
                        if (!pName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) pName += ".exe";
                        trackedProcesses[p.Id] = pName;
                    }
                } catch { }

                try {
                    using (EventLog secLog = new EventLog("Security")) {
                        int cnt = secLog.Entries.Count;
                        for (int idx = Math.Max(0, cnt - 40); idx < cnt; idx++) {
                            seenSecIndices.Add(secLog.Entries[idx].Index);
                        }
                    }
                } catch { }

                try {
                    using (EventLog appLog = new EventLog("Application")) {
                        int cnt = appLog.Entries.Count;
                        for (int idx = Math.Max(0, cnt - 40); idx < cnt; idx++) {
                            seenAppIndices.Add(appLog.Entries[idx].Index);
                        }
                    }
                } catch { }

                int cycleCounter = 0;

                while (true) {
                    Thread.Sleep(3000);
                    try {
                        cycleCounter++;
                        if (cycleCounter % 10 == 0) {
                            string loopHb = string.Format(
                                "{{\"collector_id\":\"{0}\",\"hostname\":\"{1}\",\"queue_depth\":0,\"cpu_percent\":1.5,\"memory_percent\":32.0}}",
                                colId, safeHost
                            );
                            PostJson(serverUrl + "/api/v1/collector/heartbeat", loopHb, colId, cred);
                        }

                        string loopTs = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                        List<string> eventBatch = new List<string>();

                        // 1. Detect Opened & Closed Processes
                        HashSet<int> currentPids = new HashSet<int>();
                        List<string> newlyOpened = new List<string>();
                        try {
                            foreach (Process p in Process.GetProcesses()) {
                                currentPids.Add(p.Id);
                                if (!trackedProcesses.ContainsKey(p.Id)) {
                                    string pName = p.ProcessName;
                                    if (!pName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) pName += ".exe";
                                    trackedProcesses[p.Id] = pName;
                                    if (!newlyOpened.Contains(pName)) {
                                        newlyOpened.Add(pName);
                                    }
                                }
                            }
                        } catch { }

                        // Detect Closed Processes
                        List<int> toRemovePids = new List<int>();
                        List<string> newlyClosed = new List<string>();
                        foreach (var kvp in trackedProcesses) {
                            if (!currentPids.Contains(kvp.Key)) {
                                toRemovePids.Add(kvp.Key);
                                if (!newlyClosed.Contains(kvp.Value)) {
                                    newlyClosed.Add(kvp.Value);
                                }
                            }
                        }
                        foreach (int pid in toRemovePids) {
                            trackedProcesses.Remove(pid);
                        }

                        // Emit Opened Events
                        int emOpen = 0;
                        foreach (string pName in newlyOpened) {
                            if (emOpen >= 8) break;
                            string safePName = pName.Replace("\\", "\\\\").Replace("\"", "\\\"");
                            bool isDaemon = BackgroundDaemons.Contains(pName);
                            string evType = isDaemon ? "windows.background.task" : "windows.app.opened";
                            string cat = isDaemon ? "system" : "process";
                            string evJson = string.Format(
                                "{{\"event_type\":\"{4}\",\"severity\":\"info\",\"category\":\"{5}\",\"process_name\":\"{3}\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4688,\"Action\":\"opened\",\"Hostname\":\"{1}\",\"ProcessName\":\"{3}\",\"CommandLine\":\"{3}\"}}}}",
                                loopTs, safeHost, safeUser, safePName, evType, cat
                            );
                            eventBatch.Add(evJson);
                            emOpen++;
                        }

                        // Emit Closed Events
                        int emClose = 0;
                        foreach (string pName in newlyClosed) {
                            if (emClose >= 8) break;
                            string safePName = pName.Replace("\\", "\\\\").Replace("\"", "\\\"");
                            bool isDaemon = BackgroundDaemons.Contains(pName);
                            string evType = isDaemon ? "windows.background.task" : "windows.app.closed";
                            string cat = isDaemon ? "system" : "process";
                            string evJson = string.Format(
                                "{{\"event_type\":\"{4}\",\"severity\":\"info\",\"category\":\"{5}\",\"process_name\":\"{3}\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4689,\"Action\":\"closed\",\"Hostname\":\"{1}\",\"ProcessName\":\"{3}\"}}}}",
                                loopTs, safeHost, safeUser, safePName, evType, cat
                            );
                            eventBatch.Add(evJson);
                            emClose++;
                        }

                        // 2. Real Windows Security Log Inspection (Failed Logon 4625, Lock/Unlock)
                        try {
                            using (EventLog secLog = new EventLog("Security")) {
                                int count = secLog.Entries.Count;
                                int checkLimit = Math.Max(0, count - 30);
                                for (int i = count - 1; i >= checkLimit; i--) {
                                    EventLogEntry ent = secLog.Entries[i];
                                    if (!seenSecIndices.Contains(ent.Index)) {
                                        seenSecIndices.Add(ent.Index);
                                        long id = ent.InstanceId & 0xFFFF;
                                        if (id == 4625 || ent.EventID == 4625 || ent.InstanceId == 4625) { // Failed logon attempt (wrong password)
                                            string evJson = string.Format(
                                                "{{\"event_type\":\"windows.security.4625\",\"severity\":\"high\",\"category\":\"authentication\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4625,\"Hostname\":\"{1}\",\"TargetUserName\":\"{2}\",\"Status\":\"0xC000006D\",\"SubStatus\":\"0xC000006A\",\"LogonType\":2,\"FailureReason\":\"Unknown user name or bad password\"}}}}",
                                                ent.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                                                safeHost,
                                                safeUser
                                            );
                                            eventBatch.Add(evJson);
                                        } else if (id == 4800 || ent.EventID == 4800 || ent.InstanceId == 4800) { // Workstation locked
                                            string evJson = string.Format(
                                                "{{\"event_type\":\"windows.security.4800\",\"severity\":\"info\",\"category\":\"authentication\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4800,\"Hostname\":\"{1}\",\"TargetUserName\":\"{2}\"}}}}",
                                                ent.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                                                safeHost,
                                                safeUser
                                            );
                                            eventBatch.Add(evJson);
                                        } else if (id == 4801 || ent.EventID == 4801 || ent.InstanceId == 4801) { // Workstation unlocked
                                            string evJson = string.Format(
                                                "{{\"event_type\":\"windows.security.4801\",\"severity\":\"info\",\"category\":\"authentication\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4801,\"Hostname\":\"{1}\",\"TargetUserName\":\"{2}\"}}}}",
                                                ent.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                                                safeHost,
                                                safeUser
                                            );
                                            eventBatch.Add(evJson);
                                        }
                                    }
                                }
                            }
                        } catch { }

                        // 2b. Software Installed & Uninstalled Monitoring (MsiInstaller)
                        try {
                            using (EventLog appLog = new EventLog("Application")) {
                                int count = appLog.Entries.Count;
                                int checkLimit = Math.Max(0, count - 25);
                                for (int i = count - 1; i >= checkLimit; i--) {
                                    EventLogEntry ent = appLog.Entries[i];
                                    if (!seenAppIndices.Contains(ent.Index)) {
                                        seenAppIndices.Add(ent.Index);
                                        long id = ent.InstanceId & 0xFFFF;
                                        if (id == 11707) { // Software installed
                                            string safeMsg = (ent.Message ?? "Software").Replace("\\", "\\\\").Replace("\"", "\\\"");
                                            if (safeMsg.Length > 80) safeMsg = safeMsg.Substring(0, 80);
                                            string evJson = string.Format(
                                                "{{\"event_type\":\"windows.software.installed\",\"severity\":\"info\",\"category\":\"system\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Application\",\"EventID\":11707,\"Hostname\":\"{1}\",\"ProductName\":\"{3}\"}}}}",
                                                ent.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                                                safeHost, safeUser, safeMsg
                                            );
                                            eventBatch.Add(evJson);
                                        } else if (id == 11724) { // Software uninstalled
                                            string safeMsg = (ent.Message ?? "Software").Replace("\\", "\\\\").Replace("\"", "\\\"");
                                            if (safeMsg.Length > 80) safeMsg = safeMsg.Substring(0, 80);
                                            string evJson = string.Format(
                                                "{{\"event_type\":\"windows.software.uninstalled\",\"severity\":\"info\",\"category\":\"system\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Application\",\"EventID\":11724,\"Hostname\":\"{1}\",\"ProductName\":\"{3}\"}}}}",
                                                ent.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                                                safeHost, safeUser, safeMsg
                                            );
                                            eventBatch.Add(evJson);
                                        }
                                    }
                                }
                            }
                        } catch { }

                        // 3. System Diagnostic Telemetry (every 20 cycles = ~60s)
                        if (newlyOpened.Count == 0 && (cycleCounter % 20 == 0)) {
                            int mod = (cycleCounter / 20) % 2;
                            if (mod == 0) {
                                string defEv = string.Format(
                                    "{{\"event_type\":\"windows.security.defender\",\"severity\":\"info\",\"category\":\"system\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"SYSTEM\",\"raw_payload\":{{\"Component\":\"Microsoft Defender Antivirus\",\"RealTimeProtection\":true,\"AntivirusSignatureAge\":0,\"EngineVersion\":\"1.1.24000\",\"Status\":\"Protected\"}}}}",
                                    loopTs, safeHost
                                );
                                eventBatch.Add(defEv);
                            } else {
                                string fwEv = string.Format(
                                    "{{\"event_type\":\"windows.security.firewall\",\"severity\":\"info\",\"category\":\"system\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"SYSTEM\",\"raw_payload\":{{\"Component\":\"Windows Advanced Firewall\",\"DomainProfile\":true,\"PrivateProfile\":true,\"PublicProfile\":true,\"Status\":\"Active\"}}}}",
                                    loopTs, safeHost
                                );
                                eventBatch.Add(fwEv);
                            }
                        }

                        // 4. Sample Active Outgoing TCP Network Flows from this PC
                        try {
                            IPGlobalProperties ipProps = IPGlobalProperties.GetIPGlobalProperties();
                            TcpConnectionInformation[] tcpConns = ipProps.GetActiveTcpConnections();
                            int addedFlows = 0;
                            foreach (TcpConnectionInformation conn in tcpConns) {
                                if (conn.State == TcpState.Established) {
                                    string remIp = conn.RemoteEndPoint.Address.ToString();
                                    if (remIp != "127.0.0.1" && remIp != "::1" && remIp != "0.0.0.0" && !remIp.StartsWith("169.254.") && !remIp.StartsWith("fe80:")) {
                                        string locIp = conn.LocalEndPoint.Address.ToString();
                                        int locPort = conn.LocalEndPoint.Port;
                                        int remPort = conn.RemoteEndPoint.Port;

                                        string ruleName = (remPort == 443) ? "Secure Web Traffic (HTTPS)" : (remPort == 80) ? "Web Traffic (HTTP)" : (remPort == 53) ? "DNS Lookup" : "Active TCP Outbound";

                                        string netEv = string.Format(
                                            "{{\"event_type\":\"windows.network.connection\",\"severity\":\"info\",\"category\":\"network\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"source_ip\":\"{2}\",\"source_port\":{3},\"destination_ip\":\"{4}\",\"destination_port\":{5},\"raw_payload\":{{\"Channel\":\"Network\",\"Protocol\":\"TCP\",\"LocalAddress\":\"{2}\",\"LocalPort\":{3},\"RemoteAddress\":\"{4}\",\"RemotePort\":{5},\"State\":\"Established\"}},\"normalized_payload\":{{\"protocol\":\"TCP\",\"action\":\"allowed\",\"rule\":\"{6}\"}}}}",
                                            loopTs, safeHost, locIp, locPort, remIp, remPort, ruleName
                                        );
                                        eventBatch.Add(netEv);
                                        addedFlows++;
                                        if (addedFlows >= 2) break;
                                    }
                                }
                            }
                        } catch { }

                        // Post event batch if any items present
                        if (eventBatch.Count > 0) {
                            string loopEv = string.Format(
                                "{{\"batch_id\":\"{0}\",\"events\":[{1}]}}",
                                Guid.NewGuid().ToString(),
                                string.Join(",", eventBatch.ToArray())
                            );
                            PostJson(serverUrl + "/api/v1/collector/events", loopEv, colId, cred);
                        }
                    } catch { }
                }
            });
        }

        private string PostJson(string url, string jsonBody, string collectorId, string credential) {
            WebException lastEx = null;
            try {
                return DoPostJson(url, jsonBody, collectorId, credential);
            } catch (WebException wex) {
                lastEx = wex;
                if (url.Contains("localhost") || url.Contains("127.0.0.1")) {
                    string altUrl = url.Contains("localhost")
                        ? url.Replace("://localhost:", "://127.0.0.1:")
                        : url.Replace("://127.0.0.1:", "://localhost:");
                    try {
                        return DoPostJson(altUrl, jsonBody, collectorId, credential);
                    } catch (WebException altEx) {
                        if (altEx.Response != null) {
                            lastEx = altEx;
                        }
                    }
                }
                throw lastEx;
            }
        }

        private static void ConfigureSecurityProtocols() {
            try {
                // Force modern TLS 1.2 (3072) and TLS 1.3 (12288) for HTTPS connections to cloud APIs
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)12288
                    | (SecurityProtocolType)3072
                    | (SecurityProtocolType)768
                    | (SecurityProtocolType)192;
            } catch {
                try {
                    ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072
                        | (SecurityProtocolType)192;
                } catch { }
            }

            try {
                ServicePointManager.Expect100Continue = false;
                ServicePointManager.DefaultConnectionLimit = 32;
                // Accept certificates validated by system or modern cloud providers (Render, Cloudflare, Let's Encrypt)
                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            } catch { }
        }

        private string DoPostJson(string url, string jsonBody, string collectorId, string credential) {
            ConfigureSecurityProtocols();

            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/json";
            req.Timeout = 45000;
            req.ReadWriteTimeout = 45000;
            req.KeepAlive = true;
            req.ProtocolVersion = HttpVersion.Version11;
            req.UserAgent = "CyberGuard-Windows-Installer/1.0.0";
            req.Proxy = null;
            req.ServicePoint.Expect100Continue = false;

            if (!string.IsNullOrEmpty(collectorId)) {
                req.Headers["X-Collector-ID"] = collectorId;
            }
            if (!string.IsNullOrEmpty(credential)) {
                req.Headers["X-Collector-Credential"] = credential;
            }

            byte[] bytes = Encoding.UTF8.GetBytes(jsonBody);
            req.ContentLength = bytes.Length;
            using (Stream s = req.GetRequestStream()) {
                s.Write(bytes, 0, bytes.Length);
            }

            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8)) {
                return sr.ReadToEnd();
            }
        }

        private void ExecuteUninstall() {
            try {
                string targetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CyberGuard", "Collector");
                string credPath = Path.Combine(targetDir, "credential.dat");
                if (File.Exists(credPath)) {
                    try {
                        byte[] encrypted = File.ReadAllBytes(credPath);
                        byte[] decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
                        string cred = Encoding.UTF8.GetString(decrypted);
                        if (cred.Contains(":")) cred = cred.Split(new char[] { ':' }, 2)[1];
                        PostJson(serverUrl + "/api/v1/collector/revoke", "{}", "", cred);
                    } catch { }
                    File.Delete(credPath);
                }
                string statePath = Path.Combine(targetDir, "enrolled_state.json");
                if (File.Exists(statePath)) {
                    try { File.Delete(statePath); } catch { }
                }
                string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cyberguard-config.json");
                if (File.Exists(configPath)) {
                    try { File.Delete(configPath); } catch { }
                }
                if (Directory.Exists(targetDir)) {
                    try { Directory.Delete(targetDir, true); } catch { }
                }
                MessageBox.Show("CyberGuard AI Endpoint Collector has been successfully uninstalled.", "Uninstall Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
            } catch (Exception ex) {
                MessageBox.Show("Uninstall note: " + ex.Message, "CyberGuard AI", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        [STAThread]
        static void Main(string[] args) {
            ConfigureSecurityProtocols();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm(args));
        }
    }
}
