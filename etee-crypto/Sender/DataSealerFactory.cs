/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014-2020 Egelke
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
    public static class DataSealerFactory
    {
        //todo this add tests
        public static IDataSealer Create(Level level, AsymmetricAlgorithm privateKey, byte[] keyId = null)
        {
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, privateKey, null, keyId);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for B-Level only.
        /// </summary>
        /// <param name="authSign">The certificate to use for proving the origin of the message.</param>
        /// <param name="nonRepSign">The certificate to use for non-repudiation of the message content, null (default) if not appicable (authSign used instead)</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(Level level, X509Certificate2 authSign, X509Certificate2 nonRepSign = null)
        {
            ValidateCertificates(authSign, nonRepSign);
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, authSign, nonRepSign, null, null);
        }

        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, AsymmetricAlgorithm privateKey, byte[] keyId = null)
        {
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, privateKey, timestampProvider, keyId);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <seealso cref="Create(Level, ITimestampProvider, EHealthP12)"/>
        /// <param name="authSign">The certificate to use for proving the origin of the message.</param>
        /// <param name="nonRepSign">The certificate to use for non-repudiation of the message content, null (default) if not appicable (authSign used instead)</param>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender</returns>
        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, X509Certificate2 authSign, X509Certificate2 nonRepSign = null)
        {
            ValidateCertificates(authSign, nonRepSign);
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, authSign, nonRepSign, timestampProvider, null);
        }

        public static IDataSealer CreateForTimemarkAuthority(Level level, AsymmetricAlgorithm privateKey, byte[] keyId = null)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, privateKey, null, keyId);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eHealth certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <seealso cref="CreateForTimemarkAuthority(Level, EHealthP12)"/>
        /// <param name="authSign">The certificate to use for proving the origin of the message.</param>
        /// <param name="nonRepSign">The certificate to use for non-repudiation of the message content, null (default) if not appicable (authSign used instead)</param>
        /// <param name="level">The level of the sealing, not allowed for B-Level</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender for a time-mark authority</returns>
        public static IDataSealer CreateForTimemarkAuthority(Level level, X509Certificate2 authSign, X509Certificate2 nonRepSign = null)
        {
            ValidateCertificates(authSign, nonRepSign);
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, authSign, nonRepSign, null, null);
        }


        private static void ValidateCertificates(X509Certificate2 authSign, X509Certificate2 nonRepCert) {
            if (authSign == null) throw new ArgumentNullException("authSign", "The authentication certificate must be provided");
            if (!authSign.HasPrivateKey) throw new ArgumentException("authSign", "The authentication certificate must have a private key");
            BC::X509.X509Certificate bcAuthentication = DotNetUtilities.FromX509Certificate(authSign);
            if (!bcAuthentication.GetKeyUsage()[0]) throw new ArgumentException("authSign", "The authentication certificate must have a key for signing");

            if (nonRepCert != null)
            {
                if (!nonRepCert.HasPrivateKey) throw new ArgumentException("nonRepCert", "The non-repudiation certificate must have a private key");
                BC::X509.X509Certificate bcNonRepudiation = DotNetUtilities.FromX509Certificate(nonRepCert);
                if (!bcNonRepudiation.GetKeyUsage()[1]) throw new ArgumentException("nonRepCert", "The non-repudiation certificate must have a key for non-Repudiation");
            }
        }
    }
}
