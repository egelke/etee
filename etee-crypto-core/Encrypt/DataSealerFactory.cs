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


using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Etee.Crypto.Encrypt
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
        /// Each instances has an authentication certficiate with it.  This is normaly issued by eHealth, but any 
        /// <see cref="X509Certificate2"/> will do as long as it is compliant with the eHealth End-To-End Encyption standards.
        /// The IDataSealer instance does not verify if the certificate is compliant, only the IDataUnsealer instance does that.
        /// If using a non eHealth authentication certificate, make sure it is compliant and trusted by the recieving parties.
        /// </para>
        /// <para>
        /// The certificate can be eighter loaded from the standard windows certificate store, for this the eHealth .p12 must
        /// be imported into the windows certificate store.  It is also possible to open a .p12 or .pfx file directly, but this
        /// does not work with the standard eHealth .p12 file.  The reason is that <see cref="X509Certificate2.X509Certificate2(System.Byte[], System.String)"/>
        /// only supports files with one private key, the standard eHealth .p12 files have two.  You must split the eHealth .p12
        /// into two seperate .p12 files, one for the authantication key and none for the encryption key.
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
        ///     X509Certificate2Collection mySignCerts = myStore.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, true);
        ///     
        ///     //Allow the user to select its own certificate
        ///     X509Certificate2Collection selected = X509Certificate2UI.SelectFromCollection(mySignCerts, "Sender Certificate", "Select your eHealth authentication certificate", X509SelectionFlag.SingleSelection);
        /// 
        ///     //if user did not select a certificate, nofify him he should
        ///     if (selected.Count != 1) throw new Exception("You must select a certificate");
        ///    
        ///     sealer = DataSealerFactory.Create(selected[0]);
        /// }
        /// finally
        /// {
        ///     myStore.Close();
        /// }
        /// </code>
        /// </example>
        /// <param name="sender">The (eHealth) certificate to use for signing the protected messages</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(X509Certificate2 sender)
        {
            return new TripleWrapper(sender);
        }

        public static IDataSealer Create(X509Certificate2 sender, X509Certificate2Collection extraStore)
        {
            return new TripleWrapper(sender, extraStore);
        }
    }
}
