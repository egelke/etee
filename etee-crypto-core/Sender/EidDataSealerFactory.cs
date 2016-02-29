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

namespace Egelke.EHealth.Etee.Crypto.Sender
{
    /// <summary>
    /// <see cref="IDataSealer"/> factory class for sealed message creators/senders.
    /// </summary>
    public static class EidDataSealerFactory
    {
        /// <summary>
        /// Event fired when eID card is requested.
        /// </summary>
        public static event EventHandler<EventArgs> EidCardRequest;

        /// <summary>
        /// Even fired when eID card is no longer requested, normally on insert.
        /// </summary>
        public static event EventHandler<EventArgs> EidCardRequestCancellation;

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eID certificate as sender suitable for B-Level only.
        /// </summary>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <param name="timeout">The time to wait for an eID to be inserted before failing</param>
        /// <param name="nonRepudiate"><c>true</c> to use the signing certificate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages with the inserted eID</returns>
        public static IDataSealer Create(Level level, TimeSpan timeout, bool nonRepudiate = true)
        {
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            X509Certificate2 signature;
            X509Certificate2 authentication;

            GetCertificates(timeout, out authentication, out signature);
            return new TripleWrapper(level, authentication, nonRepudiate ? signature : authentication, null, null);
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
        /// <param name="timeout">The time to wait for an eID to be inserted before failing</param>
        /// <param name="nonRepudiate"><c>true</c> to use the signing certificate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages with the inserted eID</returns>
        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, TimeSpan timeout, bool nonRepudiate = true)
        {
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            X509Certificate2 signature;
            X509Certificate2 authentication;

            GetCertificates(timeout, out authentication, out signature);
            return new TripleWrapper(level, authentication, nonRepudiate ? signature : authentication, timestampProvider, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface with eID certificate as sender suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// The returned data sealer assumes that the messages will be send via a time-mark authority and will therefore not attempt to add a time-stamp.
        /// The data sealer has not direct dependency to this time-mark authority, it is the caller that must send it himself.
        /// </remarks>
        /// <param name="level">The level of the sealing, B-Level not allowed</param>
        /// <param name="timeout">The time to wait for an eID to be inserted before failing</param>
        /// <param name="nonRepudiate"><c>true</c> to use the signing certificate</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages with the inserted eID</returns>
        public static IDataSealer CreateForTimemarkAuthority(Level level, TimeSpan timeout, bool nonRepudiate = true)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            X509Certificate2 signature;
            X509Certificate2 authentication;

            GetCertificates(timeout, out authentication, out signature);
            return new TripleWrapper(level, authentication, nonRepudiate ? signature : authentication, null, null);
        }

        private static void GetCertificates(TimeSpan timeout, out X509Certificate2 authentication, out X509Certificate2 signature)
        {
            //Read the values from the eID, request eID if needed
            X509Certificate2 auth;
            X509Certificate2 sign;
            using (Readers readers = new Readers(ReaderScope.User))
            {
                readers.EidCardRequest += readers_EidCardRequest;
                readers.EidCardRequestCancellation += readers_EidCardRequestCancellation;
                EidCard target = readers.WaitForEid(timeout);
                using (target)
                {
                    auth = target.ReadCertificate(CertificateId.Authentication);
                    sign = target.ReadCertificate(CertificateId.Signature);
                }
            }
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                X509Certificate2Collection authMatch = my.Certificates.Find(X509FindType.FindByThumbprint, auth.Thumbprint, true);
                if (authMatch.Count == 0) throw new InvalidOperationException("The eID authentication certificate could not be found in the windows store");
                authentication = authMatch[0];

                X509Certificate2Collection signMatch = my.Certificates.Find(X509FindType.FindByThumbprint, sign.Thumbprint, true);
                if (signMatch.Count == 0) throw new InvalidOperationException("The eID authentication certificate could not be found in the windows store");
                signature = signMatch[0];
            }
            finally
            {
                my.Close();
            }

            if (!authentication.HasPrivateKey) throw new InvalidOperationException("The authentication certificate must have a private key");
            if (!signature.HasPrivateKey) throw new InvalidOperationException("The signature certificate must have a private key");

            BC::X509.X509Certificate bcAuthentication = DotNetUtilities.FromX509Certificate(authentication);
            BC::X509.X509Certificate bcSignature = DotNetUtilities.FromX509Certificate(signature);
            if (signature.Issuer != authentication.Issuer) throw new InvalidOperationException("The signature certificate must have the same issuer as the authentication certificate");
            if (!bcAuthentication.SubjectDN.GetOidList().Contains(X509Name.SerialNumber)
                        || !bcSignature.SubjectDN.GetOidList().Contains(X509Name.SerialNumber)
                        || bcAuthentication.SubjectDN.GetValueList(X509Name.SerialNumber).Count != 1
                        || bcSignature.SubjectDN.GetValueList(X509Name.SerialNumber).Count != 1
                        || !bcAuthentication.SubjectDN.GetValueList(X509Name.SerialNumber)[0].Equals(bcSignature.SubjectDN.GetValueList(X509Name.SerialNumber)[0]))
            {
                throw new InvalidOperationException("The signature certificate must have the same serial number as the authentication certificate");
            }

            if (!bcAuthentication.GetKeyUsage()[0]) throw new InvalidOperationException("The authentication certificate must have a key for signing");
            if (!bcSignature.GetKeyUsage()[1]) throw new InvalidOperationException("The authentication certificate must have a key for non-Repudiation");
        }

        static void readers_EidCardRequest(object sender, EventArgs e)
        {
            if (EidCardRequest != null) EidCardRequest(sender, e);
        }

        static void readers_EidCardRequestCancellation(object sender, EventArgs e)
        {
            if (EidCardRequestCancellation != null) EidCardRequestCancellation(sender, e);
        }

        
    }
}
