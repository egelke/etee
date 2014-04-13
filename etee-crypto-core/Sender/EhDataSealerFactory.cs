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
        ///     //if user did not select a certificate, notify him he should
        ///     if (selected.Count != 1) throw new Exception("You must select a certificate");
        ///    
        ///     sealer = DataSealerFactory.Create(selected[0], null, Level.B_Level);
        /// }
        /// finally
        /// {
        ///     myStore.Close();
        /// }
        /// </code>
        /// </example>
        /// <param name="authSign">The eHealth certificate to use for proving the origin of the message.  The certificate key must be <strong>exportable</strong>!</param>
        /// <param name="authSignChain">The certificate chain of the eHealth certificate, if not present in the windows certificate store</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <returns>Instance of the IDataSealer that can be used to protect messages in name of the provided sender (i.e. authentication and signature certificate)</returns>
        public static IDataSealer Create(Level level, X509Certificate2 authSign)
        {
            ValidateCertificates(authSign);
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, authSign, null, null, null);
        }

        public static IDataSealer Create(Level level, EHealthP12 p12)
        {
            ValidateCertificates(p12["authentication"]);
            if ((level & Level.T_Level) == Level.T_Level) throw new NotSupportedException("This method can't create timestamps");

            return new TripleWrapper(level, p12["authentication"], null, null, p12.ToCollection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// Uses a time-stamp authority to indicate the time when the message was created. See the eH-I TSA module for possible implementation of existing authorities.
        /// See the message definition for which authority must be used if any, the eH-I TSA module provides clients for both eHealth and Fedict but can be extended to any
        /// authority that returns compliant time-stamp-tokens.
        /// </remarks>
        /// <param name="authSign">The eHealth certificate to use for proving the origin of the message.  The certificate key must be <strong>exportable</strong>!</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <seealso cref="Create(X509Certificate2, X509Certificate2, Level)"/>
        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, X509Certificate2 authSign)
        {
            ValidateCertificates(authSign);
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, authSign, null, timestampProvider, null);
        }

        public static IDataSealer Create(Level level, ITimestampProvider timestampProvider, EHealthP12 p12)
        {
            ValidateCertificates(p12["authentication"]);
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A time-stamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time stamping");

            return new TripleWrapper(level, p12["authentication"], null, timestampProvider, p12.ToCollection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="IDataSealer"/> interface suitable for all levels except for B-Level.
        /// </summary>
        /// <remarks>
        /// The returned data sealer assumes that the messages will be send via a time-mark authority and will therefore not attempt to add a time-stamp.
        /// The data sealer has not direct dependency to this time-mark authority, it is the caller that must send it himself.
        /// </remarks>
        /// <param name="authSign">The eHealth certificate to use for proving the origin of the message.  The certificate key must be <strong>exportable</strong>!</param>
        /// <param name="authSignChain">The certificate chain of the eHealth certificate, if not present in the windows certificate store</param>
        /// <param name="level">The level of the sealing, only B-Level is allowed (parameter present for awareness)</param>
        /// <seealso cref="Create(X509Certificate2, X509Certificate2, Level)"/>
        public static IDataSealer CreateForTimemarkAuthority(X509Certificate2Collection authSignChain, Level level, X509Certificate2 authSign)
        {
            ValidateCertificates(authSign);
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, authSign, null, null, authSignChain);
        }

        public static IDataSealer CreateForTimemarkAuthority(Level level, EHealthP12 p12)
        {
            ValidateCertificates(p12["authentication"]);
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, p12["authentication"], null, null, p12.ToCollection());
        }

        private static void ValidateCertificates(X509Certificate2 authSign) {
            if (authSign == null) throw new ArgumentNullException("authSign", "The authentication certificate must be provided");
            if (!authSign.HasPrivateKey) throw new ArgumentException("authSign", "The authentication certificate must have a private key");

            //advanced checks (for eHealth certificate)
            BC::X509.X509Certificate bcAuthentication = DotNetUtilities.FromX509Certificate(authSign);
            if (!((RSACryptoServiceProvider)authSign.PrivateKey).CspKeyContainerInfo.Exportable) throw new ArgumentException("authentication", "The authentication certificate must be exportable if no (eID) signature certificate is provided");
            if (!bcAuthentication.GetKeyUsage()[0] || !bcAuthentication.GetKeyUsage()[1]) throw new ArgumentException("authentication", "The authentication certificate must have a key for both non-Repudiation and signing");
        }
    }
}
