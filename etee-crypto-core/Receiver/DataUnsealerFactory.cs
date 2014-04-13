/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke BVBA
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
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Receiver
{

    /// <summary>
    /// <see cref="IDataUnsealer"/> factory class for sealed message receivers/readers.
    /// </summary>
    public static class DataUnsealerFactory
    {
        /// <summary>
        /// Creates an instance of the <see cref="IDataUnsealer"/> interface to unseal messages.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Can be used to unseal messages of any type of level, but for T-levels only if a 
        /// time stamp authority is used and not a time marker authority.
        /// </para>
        /// <para>
        /// The provided decryption certificates aren't checked and should include expired certificates
        /// in order to unseal historical messages.  It may even include revoked certificates, this that
        /// doesn't mean the message that is sealed with it is invalid, just that it isn't confidential any more.
        /// </para>
        /// </remarks>
        /// <param name="encCerts">Own (eHealth issued) certificates with private key that can be used to decrypt, they must have an <strong>exportable</strong> private key</param>
        /// <param name="level">The required level of the sender signatures or <c>null</c> for only basic validation without revocation checks</param>
        /// <returns>Instance of the IDataUnsealer</returns>
        public static IDataUnsealer Create(Level? level, X509Certificate2Collection encCerts)
        {
            return new TripleUnwrapper(level, null, encCerts);
        }

        public static IDataUnsealer Create(Level? level, params EHealthP12[] p12s)
        {
            return Create(level, p12s.ToCollection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataUnsealer"/> interface to unseal messages that where obtained from a time-mark authority.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Can be used to unseal messages of LT-Level and TLA-Level that where obtained from a time-mark authority.  This time-mark authority can
        /// be centrals stores like ehBox but can also be internal stores that are considered secure and don't allow messages to be altered in any way.
        /// </para>
        /// <para>
        /// The provided decryption certificates aren't checked and should include expired certificates
        /// in order to unseal historical messages.  It may even include revoked certificates, this that
        /// doesn't mean the message that is sealed with it is invalid, just that it isn't confidential any more.
        /// </para>
        /// <para>
        /// In case the message does contain a time-stamp, it will be used and the time-mark authority will be ignored.
        /// </para>
        /// </remarks>
        /// <param name="encCerts">Own (eHealth issued) certificates with private key that can be used to decrypt, they must have an <strong>exportable</strong> private key</param>
        /// <param name="level">The required level of the sender signatures, either T-Level, LT-Level or LTA-Level</param>
        /// <param name="timemarkauthority">The client of the time-mark authority</param>
        /// <returns>Instance of the IDataUnsealer for messages of the specified a time-mark authority</returns>
        public static IDataUnsealer CreateFromTimemarkAuthority(Level level, ITimemarkProvider timemarkauthority, X509Certificate2Collection encCerts)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");
            if (timemarkauthority == null) throw new ArgumentNullException("time-mark authority", "This method requires an time-mark authority specified");

            return new TripleUnwrapper(level, timemarkauthority, encCerts);
        }

        public static IDataUnsealer CreateFromTimemarkAuthority(Level level, ITimemarkProvider timemarkauthority, params EHealthP12[] p12s)
        {
            return CreateFromTimemarkAuthority(level, timemarkauthority, p12s.ToCollection());
        }

        private static X509Certificate2Collection ToCollection(this EHealthP12[] p12s)
        {
            X509Certificate2Collection encCerts = new X509Certificate2Collection();

            foreach (EHealthP12 p12 in p12s)
            {
                foreach(X509Certificate2 cert in p12.Values)
                {
                    if (cert.Subject == cert.Issuer)
                    {
                        encCerts.Add(cert);
                    }
                }
            }

            return encCerts;
        }
    }
}
