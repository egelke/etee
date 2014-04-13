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
    /// <remarks>
    /// This instance is specific for a sender, so if your program supports multiple senders it will need multiple instance.
    /// </remarks>
    public static class EidDataSealerFactory
    {
        public static event EventHandler<EventArgs> EidCardRequest;

        public static event EventHandler<EventArgs> EidCardRequestCancellation;

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface suitable for B-Level only.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Each instances has an authentication and optionally a signing certificate.  Which can either be eID or eHealth certificates.
        /// In case of eHealth certificates, only the authentication certificate must be provided, it also be used as signing certificate.
        /// In case of eID certificates, both the authentication and signing certificate of the same person should be provided, the PIN will
        /// only be requested twice because of a windows limitation.
        /// </para>
        /// <para>
        /// eHealth certificate can only be loaded from the standard windows certificate store, the eHealth provided .p12 must
        /// be imported into the windows certificate store with <strong>exportable</strong> key.  It isn't possible to use the eHealth .p12 directly, because
        /// <see cref="X509Certificate2.X509Certificate2(System.Byte[], System.String)"/>
        /// only supports files with one private key, the standard eHealth .p12 files have two.  For compatibility with the .Net Xades
        /// library, the eHealth .p12 library should be imported via the <c>EHealthP12</c>-class of the eH-I library.
        /// </para>
        /// </remarks>
        /// <param name="authentication">The eID Authentication certificate to use for proving the origin of the message.</param>
        /// <param name="signature">The eID Signature certificate to protect the content of the message</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender (i.e. authentication and signature certificate)</returns>
        public static IDataSealer Create(Level level, TimeSpan timeout)
        {
            X509Certificate2 authentication;
            X509Certificate2 signature;
            GetCertificates(timeout, out authentication, out signature);
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, authentication, signature, null, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// Uses a time-stamp authority to indicate the time when the message was created. See the eH-I TSA module for possible implementation of existing authorities.
        /// See the message definition for which authority must be used if any, the eH-I TSA module provides clients for both eHealth and Fedict but can be extended to any
        /// authority that returns compliant time-stamp-tokens.
        /// </remarks>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <seealso cref="Create(X509Certificate2, X509Certificate2, Level)"/>
        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, TimeSpan timeout)
        {
            X509Certificate2 authentication;
            X509Certificate2 signature;
            GetCertificates(timeout, out authentication, out signature);
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, authentication, signature, timestampProvider, null);
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// The returned data sealer assumes that the messages will be send via a time-mark authority and will therefore not attempt to add a time-stamp.
        /// The data sealer has not direct dependency to this time-mark authority, it is the caller that must send it himself.
        /// </remarks>
        /// <param name="authentication">The eID Authentication certificate to use for proving the origin of the message.</param>
        /// <param name="signature">The eID Signature certificate to protect the content of the message</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <seealso cref="Create(X509Certificate2, X509Certificate2, Level)"/>
        public static IDataSealer CreateForTimemarkAuthority(Level level, TimeSpan timeout)
        {
            X509Certificate2 authentication;
            X509Certificate2 signature;
            GetCertificates(timeout, out authentication, out signature);
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, authentication, signature, null, null);
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
