/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System;
using System.Security;

// General Information about an assembly is controlled through the following 
// set of attributes. Change these attribute values to modify the information
// associated with an assembly.
[assembly: AssemblyTitle(".Net ETEE for eHealth")]
[assembly: AssemblyDescription(".Net End-To-End Encryption Library for eHealth")]
[assembly: AssemblyConfiguration("Beta")]
[assembly: AssemblyCompany("Siemens IT Solutions & Services")]
[assembly: AssemblyProduct(".Net ETEE")]
[assembly: AssemblyCopyright("Copyright © Siemens IT Solutions & Services 2010")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// Setting ComVisible to false makes the types in this assembly not visible 
// to COM components.  If you need to access a type in this assembly from 
// COM, set the ComVisible attribute to true on that type.
[assembly: ComVisible(false)]

// The following GUID is for the ID of the typelib if this project is exposed to COM
[assembly: Guid("24d55f21-52a9-4d5e-95f8-715a6df8a4d1")]

// Version information for an assembly consists of the following four values:
//
//      Major Version
//      Minor Version 
//      Build Number
//      Revision
//
// You can specify all the values or you can default the Build and Revision Numbers 
// by using the '*' as shown below:
// [assembly: AssemblyVersion("1.0.*")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.3")]
[assembly: AssemblyInformationalVersion("1.0.0.0")]

[assembly: CLSCompliant(true)]
[assembly: AllowPartiallyTrustedCallers()]

#if DEBUG
[assembly: AssemblyKeyFile(@"../debug.snk")]
[assembly: InternalsVisibleTo("Siemens.eHealth.ETEE.Crypto.Test, PublicKey=002400000480000094000000060200000024000052534131000400000100010071FF766D9CC98A2D523E9948089C38B5E2FEFB2DDF4E7EC72D3487518CEA88E7CC295CEEB6999629A18B3773E0C10FE4ECEED22903FC71168C5F18AA0C837839F1AE9D21F80C19E704667159D56A008268FE6E694958B7CEB36EBA1917C0E6A0E1026BEB1DB63DCCDDBE7D9FACB80E475250AF0EEBF3C3CF073A0CACC5C0EECF")]
#else
[assembly: AssemblyKeyFile(@"../release.snk")]
#endif