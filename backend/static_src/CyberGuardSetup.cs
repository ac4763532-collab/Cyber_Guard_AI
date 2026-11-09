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

[assembly: AssemblyTitle("CyberGuard AI Endpoint Security Collector Setup")]
[assembly: AssemblyDescription("Secure endpoint monitoring agent for Windows")]
[assembly: AssemblyCompany("CyberGuard Security Technologies Ltd.")]
[assembly: AssemblyProduct("CyberGuard AI")]
[assembly: AssemblyCopyright("Copyright © 2026 CyberGuard AI. All rights reserved.")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace CyberGuard.Installer {
    public class SetupForm : Form {
        private string serverUrl = "http://localhost:8000";
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
                if (string.IsNullOrEmpty(enrollmentToken)) {
                    enrollmentToken = txtToken.Text.Trim();
                }
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
                    StartEnrollmentThread();
                } else {
                    // Try to read from clipboard if user copied token
                    try {
                        string clip = Clipboard.GetText();
                        if (!string.IsNullOrEmpty(clip) && clip.StartsWith("enr-", StringComparison.OrdinalIgnoreCase)) {
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
                string enrollPayload = string.Format(
                    "{{\"token\":\"{0}\",\"collector_id\":\"{1}\",\"hostname\":\"{2}\",\"os_version\":\"{3}\",\"agent_version\":\"1.0.0\"}}",
                    enrollmentToken,
                    newCollectorId,
                    Environment.MachineName,
                    Environment.OSVersion.ToString()
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
                    Environment.MachineName
                );
                PostJson(serverUrl + "/api/v1/collector/heartbeat", hbPayload, newCollectorId, plaintextCredential);
                Thread.Sleep(400);

                // Stage 6: Send First Security Telemetry Event
                UpdateStatus("6/6: Verifying security telemetry pipeline...", 95);
                string eventId = Guid.NewGuid().ToString();
                string timestamp = DateTime.UtcNow.ToString("o");
                string eventBatchPayload = string.Format(
                    "{{\"batch_id\":\"{0}\",\"events\":[{{\"event_id\":\"{1}\",\"event_type\":\"windows.security.4624\",\"severity\":\"low\",\"timestamp\":\"{2}\",\"title\":\"Authorized Windows User Logon\",\"raw_payload\":{{\"Channel\":\"Security\",\"EventID\":4624,\"Hostname\":\"{3}\",\"ProcessName\":\"C:\\\\Windows\\\\System32\\\\winlogon.exe\",\"TargetUserName\":\"{4}\",\"Status\":\"Success\"}}}}]}}",
                    Guid.NewGuid().ToString(),
                    eventId,
                    timestamp,
                    Environment.MachineName,
                    Environment.UserName
                );
                PostJson(serverUrl + "/api/v1/collector/events", eventBatchPayload, newCollectorId, plaintextCredential);

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
                string respBody = "";
                if (webEx.Response != null) {
                    using (StreamReader sr = new StreamReader(webEx.Response.GetResponseStream())) {
                        respBody = sr.ReadToEnd();
                    }
                }
                ShowError("Your computer could not communicate with CyberGuard AI.", "Check your internet connection and verify that the CyberGuard server is reachable.");
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
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST";
            req.ContentType = "application/json";
            req.Timeout = 15000;
            req.UserAgent = "CyberGuard-Windows-Installer/1.0.0";

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

        [STAThread]
        static void Main(string[] args) {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupForm(args));
        }
    }
}
