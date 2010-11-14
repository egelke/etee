﻿/*
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

using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Etee.Crypto.Decrypt
{
    /// <summary>
    /// <see cref="IDataUnsealer"/> factory class.
    /// </summary>
    /// <remarks>
    /// This class should be used to get an instance of the <see cref="IDataUnsealer"/>
    /// class.  This class is static, with only two static method. 
    /// </remarks>
    public static class DataUnsealerFactory
    {
        /// <summary>
        /// Creates an unaddressed-only instance of the <see cref="IAnonymousDataUnsealer"/> inferface.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Creates a generic instance for receiving, it can be used for any receiver but only for unaddressed messages.  These
        /// instances can't be used to read addressed messages, for this you must use the <see cref="Create(X509Certificate2, X509Certificate2)"/>
        /// method.
        /// The instances aren't thread safe, so you also need multiple instance or a locking mechanism if you have multiple
        /// threads.
        /// </para>
        /// </remarks>
        /// <returns>Instance of the IAnonymousDataUnsealer that can be used to open unaddressed messages only</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope")]
        public static IAnonymousDataUnsealer Create()
        {
            return new TripleUnwrapper(null, null);
        }

        /// <summary>
        /// Creates a all purpose instance of the <see cref="IDataUnsealer"/> inferface.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Creates an instance specific for one receiving party this can be is a person, company, hospital or any other entity.
        /// This instance is specific for a reciever, so if your program supports multiple receiver it will need multiple instance.
        /// The instances aren't thread safe, so you also need multiple instance or a locking mechanism if you have multiple
        /// threads.
        /// </para>
        /// <para>
        /// Each instances has an decryption certficiate with private key and authentication certifcate associated with it.
        /// These are normaly issued by eHealth, but any 
        /// <see cref="X509Certificate2"/> will do as long as it is compliant with the eHealth End-To-End Encyption standards.
        /// If using a non eHealth authentication certificate, make sure it is compliant and trusted by the recieving parties.
        /// </para>
        /// <para>
        /// The decryption certificate must have a <strong>exportable</strong> private key assosiated with it.  Decryption will fail
        /// if you use a non-exportable key.  When using a certificate from the windows certificate store, you must make sure
        /// the pkcs#12 file was imported with the "export"-flag checked.  When loading the Certificate2 instance directly from a pkcs#12 file
        /// you must mark the private key as exportable as follows:
        /// </para>
        /// </remarks>
        /// <example>
        /// Load an pkcs#12 file with exportable private key
        /// <code lang="cs">
        /// X509Certificate2 enc = new X509Certificate2("myEncStore.p12", "xxx", X509KeyStorageFlags.Exportable);
        /// </code>
        /// <code lang="vbnet">
        /// Dim enc As New X509Certificate2("myEncStore.p12", "xxx", X509KeyStorageFlags.Exportable)
        /// </code>
        /// </example>
        /// <param name="enc">The (eHealth) certificate to use for decypting the protected messages, it must have an <strong>exportable</strong> private key</param>
        /// <param name="auth">The (eHealth) certificate that was used to create the encryption certificate</param>
        /// <returns>Instance of the IDataUnsealer that can be used to open both address and non-addressed messages</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope")]
        public static IDataUnsealer Create(X509Certificate2 enc, X509Certificate2 auth)
        {
            if (enc == null) throw new ArgumentNullException("enc");
            if (auth == null) throw new ArgumentNullException("auth");

            return new TripleUnwrapper(enc, auth);
        }
    }
}