﻿/*
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


using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Org.BouncyCastle.Security;
using BC = Org.BouncyCastle;
using System.Security.Cryptography;

namespace Egelke.EHealth.Etee.Crypto.Sender
{
    /// <summary>
    /// <see cref="IDataSealer"/> factory class for sealed message creators/senders.
    /// </summary>
    /// <remarks>
    /// This instance is specific for a sender, so if your program supports multiple senders it will need multiple instance.
    /// </remarks>
    public static class EhDataSealerFactory
    {
        
        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for B-Level only.
        /// </summary>
        /// <param name="authSign">The eHealth certificate to use for proving the origin of the message.  The certificate key must be <strong>exportable</strong>!</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(Level level, X509Certificate2 authSign)
        {
            ValidateCertificates(authSign);
            ValidateAnyCertificates(authSign);
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, authSign, null, null, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for B-Level only.
        /// </summary>
        /// <example>
        /// B-Level for alice:
        /// <code lang="cs">
        /// var alice = new EHealthP12("alices_private_key_store.p12", "test");
        /// IDataSealer sealer = DataSealerFactory.Create(Level.B_Level, alice);
        /// </code>
        /// </example>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <param name="p12">The eHealth certificate as wrapper of the pkcs12 file</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(Level level, EHealthP12 p12)
        {
            ValidateCertificates(p12["authentication"]);
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, p12["authentication"], null, null, p12.ToCollection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <seealso cref="Create(Level, ITimestampProvider, EHealthP12)"/>
        /// <param name="authSign">The eHealth certificate to use for proving the origin of the message.  The certificate key must be <strong>exportable</strong>!</param>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, X509Certificate2 authSign)
        {
            ValidateCertificates(authSign);
            ValidateAnyCertificates(authSign);
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, authSign, null, timestampProvider, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// Uses a time-stamp authority to indicate the time when the message was created. See the eH-I TSA module for possible implementation of existing authorities.
        /// See the message definition for which authority must be used if any, the eH-I TSA module provides clients for both eHealth and Fedict but can be extended to any
        /// authority that returns compliant time-stamp-tokens.
        /// </remarks>
        /// <example>
        /// LTA-Level for alice, with Fedict TSA:
        /// <code lang="cs">
        /// var alice = new EHealthP12("alices_private_key_store.p12", "test");
        /// var tsa = new Rfc3161TimestampProvider(); //not representative, should be eHealth DSS.
        /// IDataSealer sealer = DataSealerFactory.Create(Level.LTA_Level, tsa, alice);
        /// </code>
        /// </example>
        /// <param name="p12">The eHealth certificate as wrapper of the pkcs12 file</param>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, EHealthP12 p12)
        {
            ValidateCertificates(p12["authentication"]);
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, p12["authentication"], null, timestampProvider, p12.ToCollection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <seealso cref="CreateForTimemarkAuthority(Level, EHealthP12)"/>
        /// <param name="authSign">The eHealth certificate to use for proving the origin of the message.  The certificate key must be <strong>exportable</strong>!</param>
        /// <param name="level">The level of the sealing, not allowed for B-Level</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender for a time-mark authority</returns>
        public static IDataSealer CreateForTimemarkAuthority(Level level, X509Certificate2 authSign)
        {
            ValidateCertificates(authSign);
            ValidateAnyCertificates(authSign);
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, authSign, null, null, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// The returned data sealer assumes that the messages will be send via a time-mark authority and will therefore not attempt to add a time-stamp.
        /// The data sealer has not direct dependency to this time-mark authority, it is the caller that must send it himself.
        /// </remarks>
        /// <example>
        /// LTA-Level for alice, TMA (any):
        /// <code lang="cs">
        /// var alice = new EHealthP12("alices_private_key_store.p12", "test");
        /// IDataSealer sealer = DataSealerFactory.CreateForTimemarkAuthority(Level.LTA_Level, alice);
        /// </code>
        /// </example>
        /// <param name="p12">The eHealth certificate as wrapper of the pkcs12 file</param>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender for a time-mark authority</returns>
        public static IDataSealer CreateForTimemarkAuthority(Level level, EHealthP12 p12)
        {
            ValidateCertificates(p12["authentication"]);
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, p12["authentication"], null, null, p12.ToCollection());
        }

        private static void ValidateCertificates(X509Certificate2 authSign) {
            if (authSign == null) throw new ArgumentNullException("authSign", "The authentication certificate must be provided");
            if (!authSign.HasPrivateKey) throw new ArgumentException("authSign", "The authentication certificate must have a private key");
        }

        private static void ValidateAnyCertificates(X509Certificate2 authSign)
        {
            BC::X509.X509Certificate bcAuthentication = DotNetUtilities.FromX509Certificate(authSign);
            if (!((RSACryptoServiceProvider)authSign.PrivateKey).CspKeyContainerInfo.Exportable) throw new ArgumentException("authentication", "The authentication certificate must be exportable if no (eID) signature certificate is provided");
            if (!bcAuthentication.GetKeyUsage()[0] || !bcAuthentication.GetKeyUsage()[1]) throw new ArgumentException("authentication", "The authentication certificate must have a key for both non-Repudiation and signing");
        }
    }
}
