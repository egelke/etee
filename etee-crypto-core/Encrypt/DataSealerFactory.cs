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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */


using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Etee.Crypto.Encrypt
{
    /// <summary>
    /// <see cref="IDataSealer"/> factory class.
    /// </summary>
    /// <remarks>
    /// This class should be used to get an instance of the <see cref="IDataSealer"/>
    /// class.  This class is static, with only one static method. 
    /// </remarks>
    public static class DataSealerFactory
    {
        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> inferface.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Creates an instance specific for one sending party this can be is a person, company, hospital or any other entity.
        /// This instance is specific for a sender, so if your program supports multiple senders it will need multiple instance.
        /// The instances aren't thread safe, so you also need multiple instance or a locking mechanism if you have multiple
        /// threads.
        /// </para>
        /// <para>
        /// Each instances has an authentication and optionally a signing certficiate.  Which can either be eID or eHealth certficiates.
        /// In case of eHealth certificates, only the authentication certificate must be provided, it will double as signing certificate.
        /// In case of eID certificates, both the authentication and siging certificate of the same person should be provided, the PIN will
        /// only be requested once.
        /// </para>
        /// <para>
        /// eHealth certificate can only be loaded from the standard windows certificate store, the eHealth provided .p12 must
        /// be imported into the windows certificate store with <strong>exportable</strong> key.  It isn't possible to use the eHealth .p12 directly, because
        /// <see cref="X509Certificate2.X509Certificate2(System.Byte[], System.String)"/>
        /// only supports files with one private key, the standard eHealth .p12 files have two.  For compatibility with the .Net Xades
        /// library, the eHealth .p12 library should be imported via the <c>EHealthP12</c>-class of the eH-I library.
        /// </para>
        /// </remarks>
        /// <example>
        /// Requesting the user to select his own authentication certificate
        /// <code lang="cs">
        /// IDataSealer sealer;
        /// 
        /// //Open the Windows certificate store, in this case my own certificates specific for my windows users.
        /// X509Store myStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        /// myStore.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        /// try
        /// {
        ///     //Filter out all non signature certificates.
        ///     X509Certificate2Collection myEhCerts = myStore.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true);
        ///     
        ///     //Allow the user to select its own certificate
        ///     X509Certificate2Collection selected = X509Certificate2UI.SelectFromCollection(myEhCerts, "Sender Certificate", "Select your eHealth certificate", X509SelectionFlag.SingleSelection);
        /// 
        ///     //if user did not select a certificate, nofify him he should
        ///     if (selected.Count != 1) throw new Exception("You must select a certificate");
        ///    
        ///     sealer = DataSealerFactory.Create(selected[0], null);
        /// }
        /// finally
        /// {
        ///     myStore.Close();
        /// }
        /// </code>
        /// </example>
        /// <param name="authentication">The eHealth or eID Authentication certificate to use for proving the origin of the message.  For eHealth certiifcates the key must be <strong>exportable</strong>!</param>
        /// <param name="signature">The eID Signature certificate to protect the content of the message, <c>null</c> in case of eHealth certficate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender (i.e. authantication and signature certificate)</returns>
        public static IDataSealer Create(X509Certificate2 authentication, X509Certificate2 signature)
        {
            return new TripleWrapper(authentication, signature, null);
        }

        public static IDataSealer Create(X509Certificate2 authentication, X509Certificate2 signature, X509Certificate2Collection extraStore)
        {
            return new TripleWrapper(authentication, signature, extraStore);
        }
    }
}
