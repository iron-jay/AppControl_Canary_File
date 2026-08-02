using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

namespace AppControl_Canary_File.Diagnostics
{
    /// <summary>
    /// Reads the machine's App Control posture. Every probe is individually guarded:
    /// a canary that crashes tells the operator nothing, so partial results always beat
    /// an exception.
    /// </summary>
    public static class AppControlProbe
    {
        private const string DeviceGuardScope = @"root\Microsoft\Windows\DeviceGuard";
        private const string CiPolicyKey = @"SYSTEM\CurrentControlSet\Control\CI\Policy";
        private const string AppLockerExeKey = @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe";

        public static AppControlReport Run()
        {
            var report = new AppControlReport();

            Probe(report, "self", () => ProbeSelf(report));
            Probe(report, "elevation", () => report.IsElevated = IsElevated());
            Probe(report, "Win32_DeviceGuard", () => ProbeDeviceGuard(report));
            Probe(report, "Smart App Control", () => ProbeSmartAppControl(report));
            Probe(report, "AppLocker", () => ProbeAppLocker(report));
            Probe(report, "active policies", () => ProbeActivePolicies(report));

            return report;
        }

        private static void Probe(AppControlReport report, string name, Action probe)
        {
            try
            {
                probe();
            }
            catch (Exception ex)
            {
                report.Notes.Add("Could not read " + name + ": " + ex.Message);
            }
        }

        /// <summary>
        /// Where we are, what we hash to, and whether we are signed. This is the half of the
        /// report that goes straight into a WDAC or AppLocker rule.
        /// </summary>
        private static void ProbeSelf(AppControlReport report)
        {
            // MainModule beats Assembly.Location: it is the path the OS actually launched,
            // which is what the policy engine evaluated.
            using (var process = Process.GetCurrentProcess())
            {
                report.ExecutablePath = process.MainModule.FileName;
            }

            using (var sha = SHA256.Create())
            using (var stream = File.OpenRead(report.ExecutablePath))
            {
                report.Sha256 = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty);
            }

            try
            {
                var cert = X509Certificate.CreateFromSignedFile(report.ExecutablePath);
                report.SignerSubject = cert.Subject;
            }
            catch (CryptographicException)
            {
                // No Authenticode signature. Expected for the stock build.
                report.SignerSubject = null;
            }
        }

        private static bool IsElevated()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        /// <summary>
        /// WDAC state. Reading Win32_DeviceGuard normally requires elevation, so a failure
        /// here is informative rather than fatal.
        /// </summary>
        private static void ProbeDeviceGuard(AppControlReport report)
        {
            using (var searcher = new ManagementObjectSearcher(DeviceGuardScope, "SELECT * FROM Win32_DeviceGuard"))
            using (var results = searcher.Get())
            {
                foreach (ManagementBaseObject item in results)
                {
                    using (item)
                    {
                        report.UserModeCodeIntegrity =
                            MapDeviceGuardStatus(item["UsermodeCodeIntegrityPolicyEnforcementStatus"]);
                        report.KernelModeCodeIntegrity =
                            MapDeviceGuardStatus(item["CodeIntegrityPolicyEnforcementStatus"]);
                    }
                    return;
                }
            }

            report.Notes.Add("Win32_DeviceGuard returned no instances; WDAC may be unavailable on this SKU.");
        }

        /// <summary>Win32_DeviceGuard enforcement values: 0 = off, 1 = audit, 2 = enforced.</summary>
        private static EnforcementState MapDeviceGuardStatus(object raw)
        {
            if (raw == null)
                return EnforcementState.Unknown;

            switch (Convert.ToInt32(raw))
            {
                case 0: return EnforcementState.Off;
                case 1: return EnforcementState.Audit;
                case 2: return EnforcementState.Enforced;
                default: return EnforcementState.Unknown;
            }
        }

        /// <summary>
        /// Smart App Control, Windows 11 only. Values: 0 = off, 1 = on, 2 = evaluation.
        /// The key is absent on Windows 10 and on machines that never had it.
        /// </summary>
        private static void ProbeSmartAppControl(AppControlReport report)
        {
            using (var key = RegistryKey
                       .OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                       .OpenSubKey(CiPolicyKey))
            {
                var value = key == null ? null : key.GetValue("VerifiedAndReputablePolicyState");
                if (value == null)
                {
                    report.SmartAppControl = EnforcementState.Off;
                    report.SmartAppControlDescription = "Not present on this OS";
                    return;
                }

                switch (Convert.ToInt32(value))
                {
                    case 0:
                        report.SmartAppControl = EnforcementState.Off;
                        report.SmartAppControlDescription = "Off (cannot be re-enabled without reinstall)";
                        break;
                    case 1:
                        report.SmartAppControl = EnforcementState.Enforced;
                        report.SmartAppControlDescription = "ENFORCED";
                        break;
                    case 2:
                        // Evaluation mode observes silently before deciding to turn itself on.
                        report.SmartAppControl = EnforcementState.Audit;
                        report.SmartAppControlDescription = "Evaluation mode (not yet blocking)";
                        break;
                    default:
                        report.SmartAppControl = EnforcementState.Unknown;
                        report.SmartAppControlDescription = "Unrecognised state: " + value;
                        break;
                }
            }
        }

        /// <summary>
        /// AppLocker EXE rules. EnforcementMode: 0 = audit, 1 = enforce; an absent key means
        /// no policy has been applied. Rules do nothing unless AppIDSvc is running.
        /// </summary>
        private static void ProbeAppLocker(AppControlReport report)
        {
            using (var key = RegistryKey
                       .OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                       .OpenSubKey(AppLockerExeKey))
            {
                var value = key == null ? null : key.GetValue("EnforcementMode");
                if (value == null)
                {
                    report.AppLockerExe = EnforcementState.Off;
                    return;
                }

                report.AppLockerExe = Convert.ToInt32(value) == 1
                    ? EnforcementState.Enforced
                    : EnforcementState.Audit;
            }

            try
            {
                using (var service = new ServiceController("AppIDSvc"))
                {
                    report.AppIdServiceRunning = service.Status == ServiceControllerStatus.Running;
                }
            }
            catch (InvalidOperationException)
            {
                report.AppIdServiceRunning = false;
            }
        }

        /// <summary>The .cip files WDAC has actually loaded. Listing them usually needs admin.</summary>
        private static void ProbeActivePolicies(AppControlReport report)
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"System32\CodeIntegrity\CiPolicies\Active");

            if (!Directory.Exists(path))
                return;

            foreach (var file in Directory.GetFiles(path, "*.cip"))
                report.ActivePolicies.Add(Path.GetFileName(file));
        }
    }
}
