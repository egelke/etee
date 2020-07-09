/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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

#if !NETSTANDARD2_0

using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Security;
using BC = Org.BouncyCastle;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X509;
using Egelke.Eid.Client;
using System.Linq;

#if !NETFRAMEWORK
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
#endif

namespace Egelke.EHealth.Etee.Crypto.Sender
{
    /// <summary>
    /// <see cref="IDataSealer"/> factory class for sealed message creators/senders that uses the inserted eID.
    /// </summary>
    /// <remarks>
    /// Since version 2.2 this class requires an eID to be present, use the eID lib directly to handle card inserts.
    /// </remarks>
    public
#if NETFRAMEWORK
        static
#endif
        class EidDataSealerFactory
    {
#if !NETFRAMEWORK
        private ILoggerFactory _loggerFactory;

        [Obsolete("Drops all logging, please use the other constructor")]
        public EidDataSealerFactory()
        {
            _loggerFactory = NullLoggerFactory.Instance;
        }

        public EidDataSealerFactory(ILoggerFactory loggerFactory)
        {
            _loggerFactory = loggerFactory;
        }
#endif

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eID certificate as sender suitable for B-Level only.
        /// </summary>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <param name="nonRepudiate"><c>true</c> to use the signing certificate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages with the inserted eID</returns>
        /// <exception cref="EidNotFoundException">No eID found</exception>
        /// <exception cref="EidException">There was an issue with the eID</exception>
        public
#if NETFRAMEWORK
            static
#endif
            IDataSealer Create(Level level, bool nonRepudiate = false)
        {
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            X509Certificate2 signature;
            X509Certificate2 authentication;

            GetCertificates(out authentication, out signature);
            return new TripleWrapper(
#if !NETFRAMEWORK
                _loggerFactory,
#endif
                level, authentication, nonRepudiate ? signature : authentication, null, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eID certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// Uses a time-stamp authority to indicate the time when the message was created. See the eH-I TSA module for possible implementation of existing authorities.
        /// See the message definition for which authority must be used if any, the eH-I TSA module provides clients for both eHealth and Fedict but can be extended to any
        /// authority that returns compliant time-stamp-tokens.
        /// </remarks>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <param name="nonRepudiate"><c>true</c> to use the signing certificate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages with the inserted eID</returns>
        /// <exception cref="EidNotFoundException">No eID found</exception>
        /// <exception cref="EidException">There was an issue with the eID</exception>
        public
#if NETFRAMEWORK
            static
#endif
            IDataSealer Create(Level level, ITimestampProvider timestampProvider, bool nonRepudiate = false)
        {
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            X509Certificate2 signature;
            X509Certificate2 authentication;

            GetCertificates(out authentication, out signature);
            return new TripleWrapper(
#if !NETFRAMEWORK
                _loggerFactory,
#endif
                level, authentication, nonRepudiate ? signature : authentication, timestampProvider, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eID certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// The returned data sealer assumes that the messages will be send via a time-mark authority and will therefore not attempt to add a time-stamp.
        /// The data sealer has not direct dependency to this time-mark authority, it is the caller that must send it himself.
        /// </remarks>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <param name="nonRepudiate"><c>true</c> to use the signing certificate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages with the inserted eID</returns>
        /// <exception cref="EidNotFoundException">No eID found</exception>
        /// <exception cref="EidException">There was an issue with the eID</exception>
        public
#if NETFRAMEWORK
            static
#endif
            IDataSealer CreateForTimemarkAuthority(Level level, bool nonRepudiate = false)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            X509Certificate2 signature;
            X509Certificate2 authentication;

            GetCertificates(out authentication, out signature);
            return new TripleWrapper(
#if !NETFRAMEWORK
                _loggerFactory,
#endif
                level, authentication, nonRepudiate ? signature : authentication, null, null);
        }

        private static void GetCertificates(out X509Certificate2 authentication, out X509Certificate2 signature)
        {
            //Read the values from the eID, request eID if needed
            X509Certificate2 auth;
            X509Certificate2 sign;
            using (Readers readers = new Readers(ReaderScope.User))
            {
                Card card = readers.ListCards().Where(c => c is EidCard).FirstOrDefault();
                if (card == null) throw new EidNotFoundException("eid not found");
                var eidCard = (EidCard)card;
                using (eidCard)
                {
                    eidCard.Open();
                    auth = eidCard.AuthCert;
                    sign = eidCard.SignCert;
                }
            }
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection authMatch = my.Certificates.Find(X509FindType.FindByThumbprint, auth.Thumbprint, true);
                if (authMatch.Count == 0) throw new EidException("The eID authentication certificate could not be found in the windows store");
                authentication = authMatch[0];

                X509Certificate2Collection signMatch = my.Certificates.Find(X509FindType.FindByThumbprint, sign.Thumbprint, true);
                if (signMatch.Count == 0) throw new EidException("The eID authentication certificate could not be found in the windows store");
                signature = signMatch[0];
            }
            finally
            {
                my.Close();
            }

            if (!authentication.HasPrivateKey) throw new EidException("The authentication certificate must have a private key");
            if (!signature.HasPrivateKey) throw new EidException("The signature certificate must have a private key");
        }
        
    }
}

#endif