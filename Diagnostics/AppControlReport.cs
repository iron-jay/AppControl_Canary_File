using System.Collections.Generic;

namespace AppControl_Canary_File.Diagnostics
{
    /// <summary>
    /// How a given enforcement mechanism is currently configured.
    /// </summary>
    public enum EnforcementState
    {
        /// <summary>State could not be read (usually because we are not elevated).</summary>
        Unknown,
        /// <summary>Mechanism is present but disabled, or not configured at all.</summary>
        Off,
        /// <summary>Mechanism logs what it would have blocked, but blocks nothing.</summary>
        Audit,
        /// <summary>Mechanism actively blocks.</summary>
        Enforced
    }

    /// <summary>
    /// The overall conclusion to show the operator. The canary running at all means
    /// nothing blocked it; the interesting question is always <i>why</i>.
    /// </summary>
    public enum Verdict
    {
        /// <summary>Nothing was configured to stop this. Expected on an unmanaged box.</summary>
        NoEnforcement,
        /// <summary>Policy is in audit mode, so this would have been blocked under enforcement.</summary>
        AuditMode,
        /// <summary>Policy is enforcing and this ran anyway. Something is wrong.</summary>
        PolicyGap,
        /// <summary>Could not read enforcement state, typically because we are not elevated.</summary>
        Indeterminate
    }

    /// <summary>One labelled line of the report, for display and for the clipboard dump.</summary>
    public sealed class ReportRow
    {
        public ReportRow(string label, string value)
        {
            Label = label;
            Value = value;
        }

        public string Label { get; private set; }
        public string Value { get; private set; }
    }

    /// <summary>
    /// Everything we managed to learn about why this executable was allowed to run.
    /// </summary>
    public sealed class AppControlReport
    {
        public string ExecutablePath { get; set; }
        public string Sha256 { get; set; }

        /// <summary>Authenticode signer subject, or null if the file carries no signature.</summary>
        public string SignerSubject { get; set; }

        public bool IsElevated { get; set; }

        public EnforcementState UserModeCodeIntegrity { get; set; }
        public EnforcementState KernelModeCodeIntegrity { get; set; }
        public EnforcementState AppLockerExe { get; set; }

        /// <summary>Smart App Control needs its own wording ("Evaluation" has no WDAC equivalent).</summary>
        public EnforcementState SmartAppControl { get; set; }
        public string SmartAppControlDescription { get; set; }

        public bool AppIdServiceRunning { get; set; }

        /// <summary>File names of the .cip policies in the active policy directory.</summary>
        public List<string> ActivePolicies { get; set; }

        /// <summary>Anything that went wrong while probing — access denied, missing WMI class, etc.</summary>
        public List<string> Notes { get; set; }

        public AppControlReport()
        {
            ActivePolicies = new List<string>();
            Notes = new List<string>();
            UserModeCodeIntegrity = EnforcementState.Unknown;
            KernelModeCodeIntegrity = EnforcementState.Unknown;
            AppLockerExe = EnforcementState.Unknown;
            SmartAppControl = EnforcementState.Unknown;
        }

        /// <summary>
        /// Enforcement wins over audit, and audit over nothing: we report the strongest
        /// mechanism that was in play, because that is the one that should have stopped us.
        /// </summary>
        public Verdict Verdict
        {
            get
            {
                if (IsEnforced(UserModeCodeIntegrity) || IsEnforced(AppLockerExe) || IsEnforced(SmartAppControl))
                    return Verdict.PolicyGap;

                if (UserModeCodeIntegrity == EnforcementState.Audit ||
                    AppLockerExe == EnforcementState.Audit ||
                    SmartAppControl == EnforcementState.Audit)
                    return Verdict.AuditMode;

                // Only claim "nothing was configured" if we actually managed to read the states.
                if (UserModeCodeIntegrity == EnforcementState.Unknown &&
                    AppLockerExe == EnforcementState.Unknown &&
                    SmartAppControl == EnforcementState.Unknown)
                    return Verdict.Indeterminate;

                return Verdict.NoEnforcement;
            }
        }

        private static bool IsEnforced(EnforcementState state)
        {
            return state == EnforcementState.Enforced;
        }

        public string VerdictHeadline
        {
            get
            {
                switch (Verdict)
                {
                    case Verdict.PolicyGap:
                        return "Policy gap: enforcement is ON and this still ran.";
                    case Verdict.AuditMode:
                        return "Audit mode: this would have been blocked under enforcement.";
                    case Verdict.Indeterminate:
                        return "Ran, but policy state is unreadable. Try again as administrator.";
                    default:
                        return "No App Control enforcement detected on this machine.";
                }
            }
        }

        /// <summary>Exit code for headless runs. Documented in the README; scripts depend on these.</summary>
        public int ExitCode
        {
            get
            {
                switch (Verdict)
                {
                    case Verdict.PolicyGap: return 20;
                    case Verdict.AuditMode: return 10;
                    case Verdict.Indeterminate: return 30;
                    default: return 0;
                }
            }
        }

        /// <summary>The report as label/value lines, shared by the window and the console output.</summary>
        public List<ReportRow> ToRows()
        {
            var rows = new List<ReportRow>
            {
                new ReportRow("Ran from", ExecutablePath ?? "(unknown)"),
                new ReportRow("SHA256", Sha256 ?? "(unavailable)"),
                new ReportRow("Signature", SignerSubject == null
                    ? "Unsigned"
                    : SignerSubject + "  (present; chain not validated)"),
                new ReportRow("Elevated", IsElevated ? "Yes" : "No"),
                new ReportRow("WDAC user-mode CI", Describe(UserModeCodeIntegrity)),
                // Kernel-mode CI governs drivers, not this EXE, and is enforced by default on
                // 64-bit Windows. Say so, or every report looks like a false alarm.
                new ReportRow("Kernel-mode CI", Describe(KernelModeCodeIntegrity) +
                    "  (drivers only; normally enforced)"),
                new ReportRow("Smart App Control", SmartAppControlDescription ?? Describe(SmartAppControl)),
                new ReportRow("AppLocker (EXE)", Describe(AppLockerExe) +
                    (AppLockerExe == EnforcementState.Unknown
                        ? string.Empty
                        : AppIdServiceRunning ? "  (AppIDSvc running)" : "  (AppIDSvc NOT running - rules inert)"))
            };

            rows.Add(new ReportRow("Active WDAC policies",
                ActivePolicies.Count == 0 ? "(none found or unreadable)" : string.Join(", ", ActivePolicies.ToArray())));

            foreach (var note in Notes)
                rows.Add(new ReportRow("Note", note));

            return rows;
        }

        private static string Describe(EnforcementState state)
        {
            switch (state)
            {
                case EnforcementState.Off: return "Off / not configured";
                case EnforcementState.Audit: return "Audit only";
                case EnforcementState.Enforced: return "ENFORCED";
                default: return "Unknown (needs admin)";
            }
        }

        /// <summary>Plain-text dump for the clipboard button and for --quiet console output.</summary>
        public string ToPlainText()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("App Control Canary - " + VerdictHeadline);
            sb.AppendLine("Machine: " + System.Environment.MachineName +
                          "   OS: " + System.Environment.OSVersion.Version +
                          "   UTC: " + System.DateTime.UtcNow.ToString("u"));
            sb.AppendLine();

            foreach (var row in ToRows())
                sb.AppendLine(row.Label.PadRight(22) + " : " + row.Value);

            return sb.ToString();
        }
    }
}
