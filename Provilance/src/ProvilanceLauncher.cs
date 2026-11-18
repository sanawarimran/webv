using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;

namespace Provilance
{
    public class ProvilanceApp : Form
    {
        private static Mutex singleInstanceMutex;
        private NotifyIcon trayIcon;
        private ContextMenu trayMenu;
        private Thread monitorThread;
        private volatile bool isStopping = false;

        private Process esProcess = null;
        private Process kibanaProcess = null;

        private string baseDir;
        private string esBatPath;
        private string kibanaBatPath;

        [STAThread]
        public static void Main(string[] args)
        {
            bool isNewInstance = false;
            singleInstanceMutex = new Mutex(true, "ProvilanceSingleInstanceMutex_2026", out isNewInstance);

            if (!isNewInstance)
            {
                // Already running - just open browser
                try
                {
                    Process.Start("http://localhost:5601");
                }
                catch { }
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ProvilanceApp());
        }

        public ProvilanceApp()
        {
            // Make form invisible
            this.WindowState = FormWindowState.Minimized;
            this.ShowInTaskbar = false;
            this.FormBorderStyle = FormBorderStyle.None;
            this.Size = new Size(0, 0);

            // Trust self-signed certificates for local HTTPS checks
            ServicePointManager.ServerCertificateValidationCallback = 
                delegate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; };

            ResolvePaths();
            InitializeTray();

            monitorThread = new Thread(new ThreadStart(StartServicesAndOpenBrowser));
            monitorThread.IsBackground = true;
            monitorThread.Start();
        }

        private void ResolvePaths()
        {
            baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // Check if running from Provilance root or bin folder
            if (File.Exists(Path.Combine(baseDir, @"core\elasticsearch\bin\elasticsearch.bat")))
            {
                esBatPath = Path.Combine(baseDir, @"core\elasticsearch\bin\elasticsearch.bat");
                kibanaBatPath = Path.Combine(baseDir, @"core\kibana\bin\kibana.bat");
            }
            else if (File.Exists(Path.Combine(baseDir, @"..\core\elasticsearch\bin\elasticsearch.bat")))
            {
                esBatPath = Path.GetFullPath(Path.Combine(baseDir, @"..\core\elasticsearch\bin\elasticsearch.bat"));
                kibanaBatPath = Path.GetFullPath(Path.Combine(baseDir, @"..\core\kibana\bin\kibana.bat"));
            }
            else
            {
                // Fallback to current directory or dev setup
                string parent = Directory.GetParent(baseDir).FullName;
                string grandParent = Directory.GetParent(parent).FullName;

                if (File.Exists(Path.Combine(grandParent, @"elasticsearch-9.4.4-windows-x86_64\elasticsearch-9.4.4\bin\elasticsearch.bat")))
                {
                    esBatPath = Path.Combine(grandParent, @"elasticsearch-9.4.4-windows-x86_64\elasticsearch-9.4.4\bin\elasticsearch.bat");
                    kibanaBatPath = Path.Combine(grandParent, @"kibana-9.4.4\bin\kibana.bat");
                }
            }
        }

        private void InitializeTray()
        {
            trayMenu = new ContextMenu();
            trayMenu.MenuItems.Add("Open Provilance Web", new EventHandler(OnOpenWeb));
            trayMenu.MenuItems.Add("-");
            trayMenu.MenuItems.Add("Restart Services", new EventHandler(OnRestartServices));
            trayMenu.MenuItems.Add("Stop & Exit", new EventHandler(OnExit));

            trayIcon = new NotifyIcon();
            trayIcon.Text = "Provilance Enterprise Intelligence";

            // Load custom icon if available, else standard Information icon
            string iconPath = Path.Combine(baseDir, @"assets\provilance.ico");
            if (!File.Exists(iconPath))
            {
                iconPath = Path.Combine(baseDir, @"..\assets\provilance.ico");
            }

            if (File.Exists(iconPath))
            {
                try
                {
                    trayIcon.Icon = new Icon(iconPath);
                }
                catch
                {
                    trayIcon.Icon = SystemIcons.Application;
                }
            }
            else
            {
                trayIcon.Icon = SystemIcons.Application;
            }

            trayIcon.ContextMenu = trayMenu;
            trayIcon.Visible = true;
            trayIcon.DoubleClick += new EventHandler(OnOpenWeb);

            ShowBalloon("Provilance is starting...", "Starting search engine and web dashboard services in background.", ToolTipIcon.Info);
        }

        private void ShowBalloon(string title, string text, ToolTipIcon icon)
        {
            if (trayIcon != null)
            {
                trayIcon.ShowBalloonTip(4000, title, text, icon);
            }
        }

        private void StartServicesAndOpenBrowser()
        {
            try
            {
                // 1. Check or start Elasticsearch
                if (!IsPortOpen("127.0.0.1", 9200))
                {
                    if (!string.IsNullOrEmpty(esBatPath) && File.Exists(esBatPath))
                    {
                        ProcessStartInfo esInfo = new ProcessStartInfo();
                        esInfo.FileName = "cmd.exe";
                        esInfo.Arguments = "/c call \"" + esBatPath + "\"";
                        esInfo.WorkingDirectory = Path.GetDirectoryName(Path.GetDirectoryName(esBatPath));
                        esInfo.CreateNoWindow = true;
                        esInfo.UseShellExecute = false;
                        esInfo.WindowStyle = ProcessWindowStyle.Hidden;

                        esProcess = Process.Start(esInfo);
                    }
                }

                // Wait for ES port 9200
                int esRetries = 0;
                while (!IsPortOpen("127.0.0.1", 9200) && esRetries < 60 && !isStopping)
                {
                    Thread.Sleep(2000);
                    esRetries++;
                }

                if (isStopping) return;

                // 2. Check or start Kibana
                if (!IsPortOpen("127.0.0.1", 5601))
                {
                    if (!string.IsNullOrEmpty(kibanaBatPath) && File.Exists(kibanaBatPath))
                    {
                        ProcessStartInfo kbInfo = new ProcessStartInfo();
                        kbInfo.FileName = "cmd.exe";
                        kbInfo.Arguments = "/c call \"" + kibanaBatPath + "\"";
                        kbInfo.WorkingDirectory = Path.GetDirectoryName(Path.GetDirectoryName(kibanaBatPath));
                        kbInfo.CreateNoWindow = true;
                        kbInfo.UseShellExecute = false;
                        kbInfo.WindowStyle = ProcessWindowStyle.Hidden;

                        kibanaProcess = Process.Start(kbInfo);
                    }
                }

                // Wait for Kibana HTTP response on 5601
                int kbRetries = 0;
                while (!IsHttpReady("http://localhost:5601") && kbRetries < 60 && !isStopping)
                {
                    Thread.Sleep(2000);
                    kbRetries++;
                }

                if (isStopping) return;

                // 3. Open Browser
                ShowBalloon("Provilance is Ready!", "Opening Provilance web interface at http://localhost:5601", ToolTipIcon.Info);
                Thread.Sleep(1000);
                Process.Start("http://localhost:5601");
            }
            catch (Exception ex)
            {
                ShowBalloon("Startup Note", "Provilance services are initializing: " + ex.Message, ToolTipIcon.Warning);
            }
        }

        private bool IsPortOpen(string host, int port)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult result = client.BeginConnect(host, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(1000);
                    if (!success) return false;
                    client.EndConnect(result);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private bool IsHttpReady(string url)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = 2000;
                req.Method = "GET";
                req.AllowAutoRedirect = true;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return (int)resp.StatusCode >= 200 && (int)resp.StatusCode < 400;
                }
            }
            catch (WebException webEx)
            {
                if (webEx.Response != null)
                {
                    // Server responded with HTTP status (e.g. 302, 401, etc.) which means web service is up!
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private void OnOpenWeb(object sender, EventArgs e)
        {
            try
            {
                Process.Start("http://localhost:5601");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not open browser: " + ex.Message, "Provilance", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnRestartServices(object sender, EventArgs e)
        {
            StopChildProcesses();
            ShowBalloon("Restarting Provilance", "Restarting services, please wait...", ToolTipIcon.Info);

            monitorThread = new Thread(new ThreadStart(StartServicesAndOpenBrowser));
            monitorThread.IsBackground = true;
            monitorThread.Start();
        }

        private void StopChildProcesses()
        {
            isStopping = true;
            try
            {
                if (kibanaProcess != null && !kibanaProcess.HasExited)
                {
                    kibanaProcess.Kill();
                }
            }
            catch { }

            try
            {
                if (esProcess != null && !esProcess.HasExited)
                {
                    esProcess.Kill();
                }
            }
            catch { }
        }

        private void OnExit(object sender, EventArgs e)
        {
            StopChildProcesses();
            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }
            Application.Exit();
        }

        protected override void SetVisibleCore(bool value)
        {
            // Keep window completely hidden
            base.SetVisibleCore(false);
        }
    }
}
