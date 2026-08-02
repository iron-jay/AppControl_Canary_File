using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;

namespace AppControl_Canary_Lite
{
    /// <summary>
    /// The lite canary answers exactly one question: did this execute?
    ///
    /// It deliberately does not read WDAC, Smart App Control or AppLocker state. Those probes
    /// need WMI and the service control manager, which on a hardened or non-WDAC machine are
    /// extra ways for the canary itself to fail - and a canary that fails for its own reasons
    /// is worse than no canary. If you are not running WDAC, use this one.
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Distinct from the full build's codes on purpose. This says "ran, and nothing was
        /// checked", so nobody can mistake it for "ran, and no policy is configured".
        /// </summary>
        private const int ExitRanUnchecked = 5;

        private const int StdOutputHandle = -11;
        private const int AttachParentProcess = -1;

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

            var details = Describe();

            if (HasFlag(args, "--quiet", "-q"))
            {
                WriteConsole(details);
                return ExitRanUnchecked;
            }

            var app = new Application();
            app.Run(new LiteBox(details));
            return ExitRanUnchecked;
        }

        /// <summary>
        /// Everything here comes from the BCL. No WMI, no registry, no services - so there is
        /// nothing that can hang or throw on a locked-down box.
        /// </summary>
        private static string Describe()
        {
            var sb = new StringBuilder();
            sb.AppendLine("App Control Canary (lite) - execution was NOT blocked.");
            sb.AppendLine("Machine: " + Environment.MachineName +
                          "   OS: " + Environment.OSVersion.Version +
                          "   UTC: " + DateTime.UtcNow.ToString("u"));
            sb.AppendLine();

            string path;
            using (var process = Process.GetCurrentProcess())
            {
                path = process.MainModule.FileName;
            }

            sb.AppendLine("Ran from   : " + path);
            sb.AppendLine("User       : " + Environment.UserDomainName + "\\" + Environment.UserName);

            try
            {
                using (var sha = SHA256.Create())
                using (var stream = File.OpenRead(path))
                {
                    sb.AppendLine("SHA256     : " +
                        BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty));
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("SHA256     : unavailable (" + ex.Message + ")");
            }

            try
            {
                sb.AppendLine("Signature  : " + X509Certificate.CreateFromSignedFile(path).Subject);
            }
            catch (CryptographicException)
            {
                sb.AppendLine("Signature  : Unsigned");
            }

            return sb.ToString();
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
        /// WinExe has no console of its own. Use the caller's stdout when there is one - a
        /// console, a pipe, or a redirect - and only borrow the parent console otherwise.
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
                "App Control Canary (lite)\r\n" +
                "\r\n" +
                "Shows whether execution was blocked. Nothing else. No WDAC/AppLocker probing.\r\n" +
                "\r\n" +
                "  (no arguments)   Show the window.\r\n" +
                "  --quiet, -q      Print to the console instead. No window.\r\n" +
                "  --help,  -h      Show this text.\r\n" +
                "\r\n" +
                "Exit codes:\r\n" +
                "   5   Ran. Execution was not blocked. No policy state was checked.\r\n" +
                "\r\n" +
                "A block never produces an exit code at all - the launch itself fails, with\r\n" +
                "Win32 error 1260 (ERROR_ACCESS_DISABLED_BY_POLICY) in the calling process.\r\n" +
                "That is what Test-CanaryPaths.ps1 watches for.";
        }
    }
}
