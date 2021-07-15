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
using BC = Org.BouncyCastle.X509;
using Org.BouncyCastle.Cms;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Utils;
using System.Security.Cryptography;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Security;
using System.Collections;
using Egelke.EHealth.Etee.Crypto.Receiver;
using System.Diagnostics;
using Egelke.EHealth.Etee.Crypto.Status;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Crypto.Parameters;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>
    /// Represents an ETK.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class represents an ETK retrieved from the ETK-Depot.  It can be used to seal messages so it can only be viewed by the party
    /// that owns the ETK and therefore has the private key corresponding to this.  It is possible, and even advised, to cache the ETK for
    /// a short period of time for often used recipients.
    /// </para>
    /// </remarks>
    public class EncryptionToken
    {
        //private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        private byte[] content;
        private CmsSignedData raw;

        /// <summary>
        /// Constructor for the string representation of the ETK. 
        /// </summary>
        /// <param name="data">Base64 encoded representation of the ETK</param>
        public EncryptionToken(string data) : this(Convert.FromBase64String(data))
        {

        }

        /// <summary>
        /// Constructor for the binary representation of the ETK.
        /// </summary>
        /// <param name="data">raw ETK</param>
        public EncryptionToken(byte[] data)
        {
            raw = new CmsSignedData(data);
        }

        internal X509Certificate2 ToCertificate()
        {
            return new X509Certificate2(Content);
        }

        /// <summary>
        /// Gets the byte representation of the ETK.
        /// </summary>
        /// <returns>Binary form of the ETK</returns>
        public byte[] GetEncoded()
        {
                return raw.GetEncoded();
        }

        /// <summary>
        /// Gets the string representation of the ETK.
        /// </summary>
        /// <returns>Base64 form of the ETK</returns>
        public String GetEncodedAsString()
        {
            return Convert.ToBase64String(raw.GetEncoded());
        }

        private byte[] Content
        {
            get
            {
                if (content == null)
                {
                    MemoryStream memStream = new MemoryStream();
                    raw.SignedContent.Write(memStream);
                    content = memStream.ToArray();
                }
                return content;
            }
        }

        /// <summary>
        /// Verifies if the ETK contains a token that is still valid and can be trusted.
        /// </summary>
        /// <remarks>
        /// Does check the revocation information of the certificates used to issue the
        /// certificate.
        /// </remarks>
        /// <seealso cref="Verify(bool)"/>
        /// <returns>Detailed information about the encryption certificate status</returns>
        public CertificateSecurityInformation Verify()
        {
            return Verify(true);

        }

        /// <summary>
        /// Verifies if the ETK contains a token that is still valid and can be trusted.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method checks if the certificate in the ETK is issued by a trusted party.  Trust means
        /// the root certificate is trusted by the computer it is running on and all
        /// validation checks, including revocation, are successful.  Root
        /// certificates are trusted by the computer if present in the 
        /// <see cref="StoreName.Root"/> store.
        /// </para>
        /// <para>
        /// This method no longer validates the signer of the ETK token due lack of signing time in the ETK.
        /// The encryption certificate inside the ETK is still completely verified, this means there isn't a reduction in
        /// security compared to the previous implementation.
        /// </para>
        /// </remarks>
        /// <param name="checkRevocation"><c>true</c>to check if the certificates that issued the encryption cert aren't revoked</param>
        /// <returns>Detailed information about the encryption certificate status</returns>
        public CertificateSecurityInformation Verify(bool checkRevocation)
        {
            IList<CertificateList> crls;
            IList<BasicOcspResponse> ocps;

            //Get encryption cert
            BC::X509Certificate encCert = DotNetUtilities.FromX509Certificate(ToCertificate());
            //trace.TraceEvent(TraceEventType.Information, 0, "Verifying ETK: {0}", encCert.SubjectDN.ToString());

            //Check the certificate
            IX509Store certs = raw.GetCertificates("COLLECTION");
            if (checkRevocation)
            {
                crls = new List<CertificateList>();
                ocps = new List<BasicOcspResponse>();
            }
            else
            {
                crls = null;
                ocps = null;
            }
            CertificateSecurityInformation certInfo = encCert.Verify(DateTime.UtcNow, new int[] { 2, 3 }, EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey, certs, ref crls, ref ocps);
            if (!(encCert.GetPublicKey() is RsaKeyParameters))
            {
                certInfo.securityViolations.Add(CertSecurityViolation.NotValidKeyType);
                //trace.TraceEvent(TraceEventType.Warning, 0, "Only RSA keys can be used for sealing");
            }
            return certInfo;
        }

    }
}
