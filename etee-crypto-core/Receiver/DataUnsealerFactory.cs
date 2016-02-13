﻿/*
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
using Org.BouncyCastle.Security;
using Egelke.EHealth.Etee.Crypto.Utils;
using Org.BouncyCastle.X509.Store;
using System.Collections;

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
        /// <seealso cref="Create(Level?, EHealthP12[])"/>
        /// <param name="encCerts">Own (eHealth issued) certificates with private key that can be used to decrypt, they must have an <strong>exportable</strong> private key</param>
        /// <param name="authCertChains">Own eHealth issued certificate that where used to create encryption certificates, with the chain if not present in the windows store</param>
        /// <param name="level">The required level of the sender signatures or <c>null</c> for only basic validation without revocation checks</param>
        /// <returns>Instance of the IDataUnsealer</returns>
        public static IDataUnsealer Create(Level? level, X509Certificate2Collection encCerts, X509Certificate2Collection authCertChains)
        {
            return new TripleUnwrapper(level, null, encCerts, ToStore(authCertChains));
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataUnsealer"/> interface to unseal messages.
        /// </summary>
        /// <para>
        /// Can be used to unseal messages of any type of level, but for T-levels only if a 
        /// time stamp authority is used and not a time marker authority.
        /// </para>
        /// <para>
        /// The provided decryption certificates aren't checked and should include expired certificates
        /// in order to unseal historical messages.  It may even include revoked certificates, this that
        /// doesn't mean the message that is sealed with it is invalid, just that it isn't confidential any more.
        /// </para>
        /// <param name="level">The required level of the sender signatures or <c>null</c> for only basic validation without revocation checks</param>
        /// <param name="p12s">Own eHealth issues certificates in the form of a eHealth pkcs12 wrapper class</param>
        /// <returns>Instance of the IDataUnsealer</returns>
        public static IDataUnsealer Create(Level? level, params EHealthP12[] p12s)
        {
            X509Certificate2Collection encCerts;
            X509Certificate2Collection allCerts;

            Extract(p12s, out encCerts, out allCerts);
            return Create(level, encCerts, allCerts);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataUnsealer"/> interface to unseal messages that where obtained from a time-mark authority.
        /// </summary>
        /// <seealso cref="CreateFromTimemarkAuthority(Level, ITimemarkProvider, EHealthP12[])"/>
        /// <param name="encCerts">Own (eHealth issued) certificates with private key that can be used to decrypt, they must have an <strong>exportable</strong> private key</param>
        /// <param name="authCertChains">Own eHealth issued certificate that where used to create encryption certificates, with the chain if not present in the windows store</param>
        /// <param name="level">The required level of the sender signatures, either T-Level, LT-Level or LTA-Level</param>
        /// <param name="timemarkauthority">The client of the time-mark authority</param>
        /// <returns>Instance of the IDataUnsealer for messages of the specified a time-mark authority</returns>
        public static IDataUnsealer CreateFromTimemarkAuthority(Level level, ITimemarkProvider timemarkauthority, X509Certificate2Collection encCerts, X509Certificate2Collection authCertChains)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");
            if (timemarkauthority == null) throw new ArgumentNullException("time-mark authority", "This method requires an time-mark authority specified");

            return new TripleUnwrapper(level, timemarkauthority, encCerts, ToStore(authCertChains));
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
        /// <param name="p12s">Own eHealth issued certificates as pkcs12 wrapper that can be used to decrypt</param>
        /// <param name="level">The required level of the sender signatures, either T-Level, LT-Level or LTA-Level</param>
        /// <param name="timemarkauthority">The client of the time-mark authority</param>
        /// <returns>Instance of the IDataUnsealer for messages of the specified a time-mark authority</returns>
        public static IDataUnsealer CreateFromTimemarkAuthority(Level level, ITimemarkProvider timemarkauthority, params EHealthP12[] p12s)
        {
            X509Certificate2Collection encCerts;
            X509Certificate2Collection allCerts;

            Extract(p12s, out encCerts, out allCerts);
            return CreateFromTimemarkAuthority(level, timemarkauthority, encCerts, allCerts);
        }

        private static IX509Store ToStore(X509Certificate2Collection certs)
        {
            ArrayList senderChainCollection = new ArrayList();
            foreach (X509Certificate2 cert in certs)
            {
                senderChainCollection.Add(DotNetUtilities.FromX509Certificate(cert));
            }
            return X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(senderChainCollection));
        }

        private static void Extract(this EHealthP12[] p12s, out X509Certificate2Collection encCerts, out X509Certificate2Collection allCerts)
        {
            //split is far from prefect, but that only means that the rest of the code has to do some better lookup
            encCerts = new X509Certificate2Collection();
            allCerts = new X509Certificate2Collection();
            foreach (EHealthP12 p12 in p12s)
            {
                foreach (X509Certificate2 cert in p12.Values)
                {
                    if (cert.HasPrivateKey)
                    {
                        encCerts.Add(cert);
                    }
                    allCerts.Add(cert);
                }
            }
        }
    }
}
