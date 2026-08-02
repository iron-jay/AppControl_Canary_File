using System.Reflection;
using System.Runtime.InteropServices;

// These land in the PE version resource, which is what WDAC FileName rules and AppLocker
// publisher rules match against.
[assembly: AssemblyTitle("AppControl_Canary_Lite")]
[assembly: AssemblyDescription("Minimal canary executable showing whether execution was blocked.")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("iron-jay")]
[assembly: AssemblyProduct("AppControl_Canary_Lite")]
[assembly: AssemblyCopyright("Copyright ©  2026")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

[assembly: ComVisible(false)]
[assembly: Guid("3f6c9a41-77d2-4b18-9e05-8c2a6d14f7b3")]

[assembly: AssemblyVersion("2.1.0.0")]
[assembly: AssemblyFileVersion("2.1.0.0")]
