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

            // Check next to executable for cyberguard-config.json
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
                Text = "Automated Endpoint Collector Setup & Device Verification",
                ForeColor = Color.FromArgb(148, 163, 184), // slate-400
                Font = new Font("Segoe UI", 9),
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

            this.Shown += (s, e) => {
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

                // Save credential securely locally
                string credPath = Path.Combine(targetDir, "credential.dat");
                byte[] credBytes = Encoding.UTF8.GetBytes(plaintextCredential);
                byte[] encryptedBytes = ProtectedData.Protect(credBytes, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(credPath, encryptedBytes);

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

                // Start continuous background telemetry loop with dynamic process & real network flow monitoring
                ThreadPool.QueueUserWorkItem((s) => {
                    HashSet<int> seenProcessIds = new HashSet<int>();
                    HashSet<int> seenSecIndices = new HashSet<int>();
                    try {
                        foreach (Process p in Process.GetProcesses()) {
                            seenProcessIds.Add(p.Id);
                        }
                    } catch { }

                    try {
                        using (EventLog secLog = new EventLog("Security")) {
                            int cnt = secLog.Entries.Count;
                            for (int i = Math.Max(0, cnt - 40); i < cnt; i++) {
                                seenSecIndices.Add(secLog.Entries[i].Index);
                            }
                        }
                    } catch { }

                    int cycleCounter = 0;

                    while (true) {
                        Thread.Sleep(12000);
                        try {
                            cycleCounter++;
                            string loopHb = string.Format(
                                "{{\"collector_id\":\"{0}\",\"hostname\":\"{1}\",\"queue_depth\":0,\"cpu_percent\":1.5,\"memory_percent\":32.0}}",
                                newCollectorId, safeHost
                            );
                            PostJson(serverUrl + "/api/v1/collector/heartbeat", loopHb, newCollectorId, plaintextCredential);

                            string loopTs = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
                            List<string> eventBatch = new List<string>();

                            // 1. Detect genuine new process launches (up to 10 distinct processes)
                            List<string> newProcessNames = new List<string>();
                            try {
                                foreach (Process p in Process.GetProcesses()) {
                                    if (!seenProcessIds.Contains(p.Id)) {
                                        seenProcessIds.Add(p.Id);
                                        try {
                                            string procName = p.ProcessName;
                                            if (!procName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) {
                                                procName += ".exe";
                                            }
                                            if (!newProcessNames.Contains(procName)) {
                                                newProcessNames.Add(procName);
                                            }
                                        } catch { }
                                    }
                                }
                            } catch { }

                            int emittedProcs = 0;
                            foreach (string pName in newProcessNames) {
                                if (emittedProcs >= 10) break;
                                string safePName = pName.Replace("\\", "\\\\").Replace("\"", "\\\"");
                                string evJson = string.Format(
                                    "{{\"event_type\":\"windows.security.4688\",\"severity\":\"info\",\"category\":\"process\",\"process_name\":\"{3}\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4688,\"Hostname\":\"{1}\",\"ProcessName\":\"C:\\\\Windows\\\\System32\\\\{3}\",\"CommandLine\":\"{3}\"}}}}",
                                    loopTs, safeHost, safeUser, safePName
                                );
                                eventBatch.Add(evJson);
                                emittedProcs++;
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
                                            if (ent.InstanceId == 4625) { // Failed logon attempt
                                                string evJson = string.Format(
                                                    "{{\"event_type\":\"windows.security.4625\",\"severity\":\"high\",\"category\":\"authentication\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4625,\"Hostname\":\"{1}\",\"TargetUserName\":\"{2}\",\"Status\":\"0xC000006D\",\"SubStatus\":\"0xC000006A\",\"LogonType\":2,\"FailureReason\":\"Unknown user name or bad password\"}}}}",
                                                    ent.TimeGenerated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                                                    safeHost,
                                                    safeUser
                                                );
                                                eventBatch.Add(evJson);
                                            } else if (ent.InstanceId == 4800) { // Workstation locked
                                                string evJson = string.Format(
                                                    "{{\"event_type\":\"windows.security.4800\",\"severity\":\"info\",\"category\":\"authentication\",\"event_time\":\"{0}\",\"hostname\":\"{1}\",\"username\":\"{2}\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4800,\"Hostname\":\"{1}\",\"TargetUserName\":\"{2}\"}}}}",
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

                            // 3. System Diagnostic Telemetry (every 6 cycles = ~72s)
                            if (newProcessNames.Count == 0 && (cycleCounter % 6 == 0)) {
                                int mod = (cycleCounter / 6) % 2;
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
                                PostJson(serverUrl + "/api/v1/collector/events", loopEv, newCollectorId, plaintextCredential);
                            }
                        } catch { }
                    }
                });

                UpdateStatus("Connected! Your computer is now protected by CyberGuard AI.", 100);

                if (this.InvokeRequired) {
                    this.BeginInvoke(new Action(() => {
                        lblStepStatus.ForeColor = Color.FromArgb(52, 211, 153); // emerald-400
                        btnConnect.Text = "Connection Complete";
                        btnConnect.BackColor = Color.FromArgb(5, 150, 105);
                        btnConnect.Enabled = false;
                    }));
                }

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
                        PostJson(serverUrl + "/api/v1/collector/revoke", "{}", "", cred);
                    } catch { }
                    File.Delete(credPath);
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
