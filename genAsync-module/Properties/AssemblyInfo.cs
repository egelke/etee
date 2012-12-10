using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("eH-I GenAsync Client")]
[assembly: AssemblyDescription("CIN Generic Asynchronous Interoperability library")]
[assembly: AssemblyConfiguration("Beta")]
[assembly: AssemblyCompany("Egelke BVBA")]
[assembly: AssemblyProduct("eHealth-Interoperability")]
[assembly: AssemblyCopyright("Copyright © Egelke BVBA 2012")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]


[assembly: ComVisible(false)]

[assembly: Guid("c84bc2b9-f074-4918-a777-d63b2dbc27aa")]

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

#if DEBUG
[assembly: AssemblyKeyFile(@"../debug.snk")]
#else
[assembly: AssemblyKeyFile(@"../release.snk")]
#endif
