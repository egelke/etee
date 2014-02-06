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
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Egelke.EHealth.Etee.Crypto.Decrypt
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
        /// Only for unaddressed messages, these
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
            return new TripleUnwrapper(null);
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
        /// The decryption certificates must have an eHealth encryption certificate with an <strong>exportable</strong> private key 
        /// from the windows certificate store.  The collection shoud also contain the expired certificates in case the instance
        /// will be used to unseal old messages.
        /// </para>
        /// </remarks>
        /// <param name="encCerts">The (eHealth) certificates to use for decypting the protected messages, they must have an <strong>exportable</strong> private key</param>
        /// <returns>Instance of the IDataUnsealer that can be used to open both address and non-addressed messages</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope")]
        public static IDataUnsealer Create(X509Certificate2Collection encCerts)
        {
            if (encCerts == null) throw new ArgumentNullException("encCerts");
            if (encCerts.Count == 0) throw new ArgumentException("There should be at least one encryption certificate", "encCerts");

            return new TripleUnwrapper(encCerts);
        }
    }
}
