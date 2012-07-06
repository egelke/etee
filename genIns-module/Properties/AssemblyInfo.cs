using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("eH-I GenINS Client")]
[assembly: AssemblyDescription("CIN Generic Insurability Interoperability library")]
[assembly: AssemblyConfiguration("Beta")]
[assembly: AssemblyCompany("Egelke BVBA")]
[assembly: AssemblyProduct("eHealth-Interoperability")]
[assembly: AssemblyCopyright("Copyright © Egelke BVBA 2012")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]


[assembly: ComVisible(false)]

[assembly: Guid("c75bb058-4dd5-42a1-a5b0-0b6cbf56f1b2")]

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

#if DEBUG
[assembly: AssemblyKeyFile(@"../debug.snk")]
#else
[assembly: AssemblyKeyFile(@"../release.snk")]
#endif