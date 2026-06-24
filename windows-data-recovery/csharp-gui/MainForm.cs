using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RecoveryMvp.Gui
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "Recovery MVP GUI (Launcher)";
            this.Width = 800;
            this.Height = 600;

            var btnRun = new Button { Text = "Run Python GUI", Left = 10, Top = 10, Width = 150 };
            btnRun.Click += (_, __) => RunPythonGui();
            this.Controls.Add(btnRun);

            var btnScan = new Button { Text = "Run Console Scan (example)", Left = 170, Top = 10, Width = 200 };
            btnScan.Click += async (_, __) => await RunExampleScanAsync();
            this.Controls.Add(btnScan);

            var txtLog = new TextBox { Multiline = true, Left = 10, Top = 50, Width = 760, Height = 480, ScrollBars = ScrollBars.Both };
            txtLog.Name = "txtLog";
            this.Controls.Add(txtLog);
        }

        private void AppendLog(string text)
        {
            var txt = this.Controls["txtLog"] as TextBox;
            if (txt == null) return;
            if (txt.InvokeRequired)
            {
                txt.Invoke(new Action(() => txt.AppendText(text + Environment.NewLine)));
            }
            else
            {
                txt.AppendText(text + Environment.NewLine);
            }
        }

        private void RunPythonGui()
        {
            try
            {
                var psi = new ProcessStartInfo("python", "recovery_gui.py")
                {
                    WorkingDirectory = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..")),
                    UseShellExecute = true
                };
                Process.Start(psi);
                AppendLog("Launched Python GUI.");
            }
            catch (Exception ex)
            {
                AppendLog("Failed to launch Python GUI: " + ex.Message);
            }
        }

        private async Task RunExampleScanAsync()
        {
            AppendLog("Starting example scan (this launches the console tool)...");
            await Task.Run(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo("dotnet", "run --project ..\\RecoveryMvp.csproj -- scan --source sample.img --output recovered")
                    {
                        WorkingDirectory = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..")),
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                    };

                    using var proc = Process.Start(psi);
                    if (proc == null)
                    {
                        AppendLog("Failed to start process.");
                        return;
                    }

                    while (!proc.StandardOutput.EndOfStream)
                    {
                        var line = proc.StandardOutput.ReadLine();
                        AppendLog(line);
                    }

                    proc.WaitForExit();
                    AppendLog($"Console scan exited with code {proc.ExitCode}");
                }
                catch (Exception ex)
                {
                    AppendLog("Error running console scan: " + ex.Message);
                }
            });
        }
    }
}
