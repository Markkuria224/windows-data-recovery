using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace RecoveryMvp.Gui
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
        }

        public static int RunPythonScan(string args)
        {
            // placeholder
            return 0;
        }
    }
}
