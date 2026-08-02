using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using AppControl_Canary_File.Diagnostics;

namespace AppControl_Canary_File
{
    internal class Program
    {
        private const int AttachParentProcess = -1;

        private const int StdOutputHandle = -11;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);

        [STAThread]
        static int Main(string[] args)
        {
            if (HasFlag(args, "--help", "-h", "/?"))
            {
                WriteConsole(HelpText());
                return 0;
            }

            AppControlReport report;
            try
            {
                report = AppControlProbe.Run();
            }
            catch (Exception ex)
            {
                WriteConsole("Canary diagnostics failed: " + ex.Message);
                return 1;
            }

            if (HasFlag(args, "--quiet", "-q"))
            {
                WriteConsole(report.ToPlainText());
                return report.ExitCode;
            }

            var app = new Application();
            app.Run(new MessBox(report));
            return report.ExitCode;
        }

        private static bool HasFlag(string[] args, params string[] names)
        {
            foreach (var arg in args)
                foreach (var name in names)
                    if (string.Equals(arg, name, StringComparison.OrdinalIgnoreCase))
                        return true;

            return false;
        }

        /// <summary>
        /// This is a WinExe, so it has no console of its own. If the caller handed us a usable
        /// stdout - an inherited console, a pipe, or a file redirect - write there and leave it
        /// alone; scripts redirect us and would otherwise get nothing. Only borrow the parent's
        /// console when we have no handle at all. Launched from Explorer there is neither, and
        /// we stay silent.
        /// </summary>
        private static void WriteConsole(string text)
        {
            var handle = GetStdHandle(StdOutputHandle);
            var haveStdout = handle != IntPtr.Zero && handle != new IntPtr(-1);

            if (!haveStdout && !AttachConsole(AttachParentProcess))
                return;

            var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            Console.SetOut(stdout);
            Console.WriteLine();
            Console.WriteLine(text);
        }

        private static string HelpText()
        {
            return
                "App Control Canary\r\n" +
                "\r\n" +
                "  (no arguments)   Show the diagnostics window.\r\n" +
                "  --quiet, -q      Print the report to the console instead. No window.\r\n" +
                "  --help,  -h      Show this text.\r\n" +
                "\r\n" +
                "Exit codes (the canary running at all means nothing blocked it):\r\n" +
                "   0   Ran; no App Control enforcement is configured.\r\n" +
                "  10   Ran; policy is in audit mode and would have blocked this.\r\n" +
                "  20   Ran; policy is ENFORCING and failed to block this. Policy gap.\r\n" +
                "  30   Ran; policy state could not be read. Retry as administrator.\r\n" +
                "   1   Diagnostics failed.";
        }
    }
}
