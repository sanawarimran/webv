using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Windows.Forms;

namespace Provilance
{
    public class StopApp
    {
        [STAThread]
        public static void Main(string[] args)
        {
            int killed = 0;
            try
            {
                // Kill java and node processes started for elasticsearch and kibana
                Process[] processes = Process.GetProcesses();
                foreach (Process p in processes)
                {
                    try
                    {
                        string name = p.ProcessName.ToLower();
                        if (name == "java" || name == "node")
                        {
                            // Check command line or kill if in Provilance
                            p.Kill();
                            killed++;
                        }
                    }
                    catch { }
                }

                MessageBox.Show(
                    "Provilance background services have been stopped successfully.",
                    "Provilance",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Error stopping services: " + ex.Message,
                    "Provilance",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
            }
        }
    }
}
