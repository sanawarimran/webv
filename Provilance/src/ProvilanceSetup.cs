using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace Provilance
{
    public class InstallerForm : Form
    {
        private Label lblTitle;
        private Label lblSubtitle;
        private Label lblPath;
        private TextBox txtInstallPath;
        private Button btnBrowse;
        private CheckBox chkDesktopShortcut;
        private CheckBox chkStartMenuShortcut;
        private ProgressBar progressBar;
        private Label lblStatus;
        private Button btnInstall;
        private CheckBox chkLaunchNow;
        private BackgroundWorker worker;

        private string sourceDir;

        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InstallerForm());
        }

        public InstallerForm()
        {
            sourceDir = AppDomain.CurrentDomain.BaseDirectory;

            this.Text = "Provilance Enterprise Intelligence - Setup";
            this.Size = new Size(580, 420);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;

            string iconPath = Path.Combine(sourceDir, @"assets\provilance.ico");
            if (File.Exists(iconPath))
            {
                try { this.Icon = new Icon(iconPath); } catch { }
            }

            // Header Panel
            Panel header = new Panel();
            header.Dock = DockStyle.Top;
            header.Height = 70;
            header.BackColor = Color.FromArgb(15, 32, 67);

            lblTitle = new Label();
            lblTitle.Text = "Provilance Setup";
            lblTitle.Font = new Font("Segoe UI", 16, FontStyle.Bold);
            lblTitle.ForeColor = Color.White;
            lblTitle.Location = new Point(20, 10);
            lblTitle.AutoSize = true;
            header.Controls.Add(lblTitle);

            lblSubtitle = new Label();
            lblSubtitle.Text = "Install Provilance Search & Analytics Platform on your computer.";
            lblSubtitle.Font = new Font("Segoe UI", 9, FontStyle.Regular);
            lblSubtitle.ForeColor = Color.FromArgb(180, 210, 240);
            lblSubtitle.Location = new Point(22, 40);
            lblSubtitle.AutoSize = true;
            header.Controls.Add(lblSubtitle);

            this.Controls.Add(header);

            // Install Path
            lblPath = new Label();
            lblPath.Text = "Installation Directory:";
            lblPath.Location = new Point(25, 90);
            lblPath.AutoSize = true;
            this.Controls.Add(lblPath);

            txtInstallPath = new TextBox();
            txtInstallPath.Text = @"C:\Provilance";
            txtInstallPath.Location = new Point(25, 115);
            txtInstallPath.Size = new Size(420, 24);
            this.Controls.Add(txtInstallPath);

            btnBrowse = new Button();
            btnBrowse.Text = "Browse...";
            btnBrowse.Location = new Point(455, 113);
            btnBrowse.Size = new Size(85, 26);
            btnBrowse.Click += new EventHandler(OnBrowse);
            this.Controls.Add(btnBrowse);

            // Options
            chkDesktopShortcut = new CheckBox();
            chkDesktopShortcut.Text = "Create Desktop Shortcut";
            chkDesktopShortcut.Checked = true;
            chkDesktopShortcut.Location = new Point(25, 160);
            chkDesktopShortcut.AutoSize = true;
            this.Controls.Add(chkDesktopShortcut);

            chkStartMenuShortcut = new CheckBox();
            chkStartMenuShortcut.Text = "Create Start Menu Shortcuts";
            chkStartMenuShortcut.Checked = true;
            chkStartMenuShortcut.Location = new Point(25, 190);
            chkStartMenuShortcut.AutoSize = true;
            this.Controls.Add(chkStartMenuShortcut);

            // Progress Bar
            progressBar = new ProgressBar();
            progressBar.Location = new Point(25, 230);
            progressBar.Size = new Size(515, 22);
            progressBar.Visible = false;
            this.Controls.Add(progressBar);

            lblStatus = new Label();
            lblStatus.Text = "Ready to install.";
            lblStatus.Location = new Point(25, 260);
            lblStatus.Size = new Size(515, 20);
            this.Controls.Add(lblStatus);

            chkLaunchNow = new CheckBox();
            chkLaunchNow.Text = "Launch Provilance immediately after setup";
            chkLaunchNow.Checked = true;
            chkLaunchNow.Location = new Point(25, 290);
            chkLaunchNow.AutoSize = true;
            this.Controls.Add(chkLaunchNow);

            // Install Button
            btnInstall = new Button();
            btnInstall.Text = "Install";
            btnInstall.Location = new Point(435, 330);
            btnInstall.Size = new Size(105, 32);
            btnInstall.BackColor = Color.FromArgb(33, 147, 176);
            btnInstall.ForeColor = Color.White;
            btnInstall.FlatStyle = FlatStyle.Flat;
            btnInstall.Font = new Font("Segoe UI", 9, FontStyle.Bold);
            btnInstall.Click += new EventHandler(OnInstallClick);
            this.Controls.Add(btnInstall);

            worker = new BackgroundWorker();
            worker.WorkerReportsProgress = true;
            worker.DoWork += new DoWorkEventHandler(Worker_DoWork);
            worker.ProgressChanged += new ProgressChangedEventHandler(Worker_ProgressChanged);
            worker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(Worker_RunWorkerCompleted);
        }

        private void OnBrowse(object sender, EventArgs e)
        {
            using (FolderBrowserDialog fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select Provilance Installation Directory";
                if (fbd.ShowDialog() == DialogResult.OK)
                {
                    txtInstallPath.Text = fbd.SelectedPath;
                }
            }
        }

        private void OnInstallClick(object sender, EventArgs e)
        {
            btnInstall.Enabled = false;
            btnBrowse.Enabled = false;
            txtInstallPath.Enabled = false;
            progressBar.Visible = true;
            lblStatus.Text = "Preparing installation files...";

            worker.RunWorkerAsync(txtInstallPath.Text.Trim());
        }

        private void Worker_DoWork(object sender, DoWorkEventArgs e)
        {
            string targetDir = (string)e.Argument;

            if (!Directory.Exists(targetDir))
            {
                Directory.CreateDirectory(targetDir);
            }

            // 1. Copy Assets & Binaries
            worker.ReportProgress(10, "Copying Provilance core binaries...");
            string targetAssets = Path.Combine(targetDir, "assets");
            if (!Directory.Exists(targetAssets)) Directory.CreateDirectory(targetAssets);

            string srcIcon = Path.Combine(sourceDir, @"assets\provilance.ico");
            if (File.Exists(srcIcon))
            {
                File.Copy(srcIcon, Path.Combine(targetAssets, "provilance.ico"), true);
            }

            string srcLauncher = Path.Combine(sourceDir, "Provilance.exe");
            if (File.Exists(srcLauncher))
            {
                File.Copy(srcLauncher, Path.Combine(targetDir, "Provilance.exe"), true);
            }

            string srcStop = Path.Combine(sourceDir, "Stop-Provilance.exe");
            if (File.Exists(srcStop))
            {
                File.Copy(srcStop, Path.Combine(targetDir, "Stop-Provilance.exe"), true);
            }

            worker.ReportProgress(30, "Setting up core directory structure...");
            string coreDir = Path.Combine(targetDir, "core");
            if (!Directory.Exists(coreDir)) Directory.CreateDirectory(coreDir);

            // Check if core/elasticsearch and core/kibana exist in parent
            string parentDir = Directory.GetParent(sourceDir).FullName;
            string esSource = Path.Combine(parentDir, @"elasticsearch-9.4.4-windows-x86_64\elasticsearch-9.4.4");
            string kbSource = Path.Combine(parentDir, @"kibana-9.4.4");

            string esTarget = Path.Combine(coreDir, "elasticsearch");
            string kbTarget = Path.Combine(coreDir, "kibana");

            worker.ReportProgress(50, "Configuring Provilance search engine...");
            CopyDirectorySafe(esSource, esTarget, worker, 50, 70);

            worker.ReportProgress(70, "Configuring Provilance dashboard...");
            CopyDirectorySafe(kbSource, kbTarget, worker, 70, 90);

            // 2. Create Shortcuts
            worker.ReportProgress(90, "Creating Windows shortcuts...");
            string exePath = Path.Combine(targetDir, "Provilance.exe");
            string stopPath = Path.Combine(targetDir, "Stop-Provilance.exe");
            string iconTarget = Path.Combine(targetAssets, "provilance.ico");

            if (chkDesktopShortcut.Checked)
            {
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                CreateWindowsShortcut(Path.Combine(desktopPath, "Provilance.lnk"), exePath, targetDir, iconTarget, "Provilance Enterprise Intelligence");
            }

            if (chkStartMenuShortcut.Checked)
            {
                string startMenuPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Provilance");
                if (!Directory.Exists(startMenuPath)) Directory.CreateDirectory(startMenuPath);

                CreateWindowsShortcut(Path.Combine(startMenuPath, "Provilance.lnk"), exePath, targetDir, iconTarget, "Provilance Web Interface");
                CreateWindowsShortcut(Path.Combine(startMenuPath, "Stop Provilance.lnk"), stopPath, targetDir, iconTarget, "Stop Provilance Services");
            }

            worker.ReportProgress(100, "Installation complete!");
            e.Result = targetDir;
        }

        private void CopyDirectorySafe(string src, string dest, BackgroundWorker bw, int startPct, int endPct)
        {
            if (!Directory.Exists(src)) return;
            if (!Directory.Exists(dest)) Directory.CreateDirectory(dest);

            string[] files = Directory.GetFiles(src, "*.*", SearchOption.AllDirectories);
            int total = files.Length;
            if (total == 0) return;

            for (int i = 0; i < total; i++)
            {
                string file = files[i];
                string rel = file.Substring(src.Length).TrimStart('\\');
                string targetFile = Path.Combine(dest, rel);
                string targetSubDir = Path.GetDirectoryName(targetFile);
                if (!Directory.Exists(targetSubDir)) Directory.CreateDirectory(targetSubDir);

                try
                {
                    File.Copy(file, targetFile, true);
                }
                catch { }

                if (i % 200 == 0)
                {
                    int currentPct = startPct + (int)(((double)i / total) * (endPct - startPct));
                    bw.ReportProgress(currentPct, "Copying " + Path.GetFileName(file) + "...");
                }
            }
        }

        private void CreateWindowsShortcut(string shortcutPath, string targetPath, string workDir, string iconLocation, string desc)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return;
                dynamic shell = Activator.CreateInstance(shellType);
                dynamic shortcut = shell.CreateShortcut(shortcutPath);
                shortcut.TargetPath = targetPath;
                shortcut.WorkingDirectory = workDir;
                shortcut.WindowStyle = 1;
                shortcut.Description = desc;
                if (File.Exists(iconLocation))
                {
                    shortcut.IconLocation = iconLocation;
                }
                shortcut.Save();
            }
            catch { }
        }

        private void Worker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            progressBar.Value = Math.Min(100, Math.Max(0, e.ProgressPercentage));
            lblStatus.Text = (string)e.UserState;
        }

        private void Worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            progressBar.Value = 100;
            lblStatus.Text = "Provilance is successfully installed!";
            lblStatus.ForeColor = Color.Green;
            btnInstall.Text = "Finish";
            btnInstall.Enabled = true;
            btnInstall.Click -= new EventHandler(OnInstallClick);
            btnInstall.Click += new EventHandler(OnFinishClick);

            string targetDir = (string)e.Result;
            if (chkLaunchNow.Checked && !string.IsNullOrEmpty(targetDir))
            {
                string exe = Path.Combine(targetDir, "Provilance.exe");
                if (File.Exists(exe))
                {
                    try { Process.Start(exe); } catch { }
                }
            }
        }

        private void OnFinishClick(object sender, EventArgs e)
        {
            Application.Exit();
        }
    }
}
