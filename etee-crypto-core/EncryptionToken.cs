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
using BC = Org.BouncyCastle.X509;
using Org.BouncyCastle.Cms;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Utils;
using System.Security.Cryptography;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Security;
using System.Collections;
using Egelke.EHealth.Etee.Crypto.Decrypt;
using System.Diagnostics;
using Egelke.EHealth.Etee.Crypto.Utils;
using Egelke.EHealth.Etee.Crypto.Status;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>
    /// Represents an ETK.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Thi class represents an ETK retrieved from the ETK-Depot.  It can be used to seal messages so it can only be viewed by the party
    /// that owns the ETK and therefore has the private key corresponding to this.  It is possible, and even advised, to cache the ETK for
    /// parties you will probably require in the future.
    /// </para>
    /// </remarks>
    public class EncryptionToken
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        private byte[] content;
        private CmsSignedData raw;

        /// <summary>
        /// Constructor for the string representation of the ETK. 
        /// </summary>
        /// <remarks>
        /// <para>
        /// The xml representation of the "GetEtkResponse" of the ETK-Depot web service
        /// contains an element "ETK" of which is content can be provided to this
        /// constructor.  Normaly you will not have access to the xml representation,
        /// so it is unlikely you will need this constuctor for this reason.
        /// </para>
        /// <para>
        /// If you use a cache that can't handle binary data, use this constuctor
        /// to use an instance from cache.
        /// </para>
        /// </remarks>
        /// <param name="data">Base64 encoded representation of the ETK</param>
        public EncryptionToken(string data) : this(Convert.FromBase64String(data))
        {

        }

        /// <summary>
        /// Constructor for the binary represenation of the ETK.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The binary represenation of the "GetEtkResponse" of the ETK-Depot web service
        /// contains an byte array item that can be provided to this constructor.
        /// </para>
        /// <para>
        /// If you use a cahce that can handle binary data, use this constructor
        /// to use an instance from cache.
        /// </para>
        /// </remarks>
        /// <param name="data">raw ETK</param>
        public EncryptionToken(byte[] data)
        {
            raw = new CmsSignedData(data);
        }

        internal BC::X509Certificate ToBCCertificate()
        {
            BC::X509CertificateParser parser = new BC::X509CertificateParser();
            return parser.ReadCertificate(Content);
        }

        /// <summary>
        /// Gets the byte representation of the ETK.
        /// </summary>
        /// <returns>Binary form of the ETK, should be saved in a cache</returns>
        public byte[] GetEncoded()
        {
                return raw.GetEncoded();
        }

        /// <summary>
        /// Gets the string representation of the ETK.
        /// </summary>
        /// <returns>String form of the ETK, should be saved in a cache</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
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
        /// <para>
        /// This method checks if the certificate in the ETK is issued by a trusted party.  Tust means
        /// the root certificate is trusted by the computer it is running on and all
        /// validation checks, including revocation, are successful.  Root
        /// certificates are trusted by the computer if present in the 
        /// <see cref="StoreName.Root"/> store.
        /// </para>
        /// <para>
        /// This method no longer validates the signer of the ETK token due lack of signing time in the ETK.
        /// The encryption certificate inside the ETK is still completley verified, this means there isn't a reduction in
        /// security compared to the previous implementation.
        /// </para>
        /// </remarks>
        /// <returns>Detailed information about the encryption certificate status</returns>
        public CertificateSecurityInformation Verify()
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying ETK: {0}", ToBCCertificate().SubjectDN.ToString());

            BC::X509Certificate encCert;
            BC::X509Certificate authCert = null;

            //Get encryption cert
            encCert = ToBCCertificate();

            //Get authentication cert
            IX509Store certs = raw.GetCertificates("COLLECTION");
            SignerID authCertSelector = new SignerID();
            authCertSelector.Subject = encCert.IssuerDN;
            ICollection authCertMatch = certs.GetMatches(authCertSelector);
            if (authCertMatch.Count != 1)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Authentication certificate not found in ETK");
                throw new InvalidMessageException("The ETK does not contain the authentication certificate");
            }
            IEnumerator iterator = authCertMatch.GetEnumerator();
            if (!iterator.MoveNext())
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Certificate present but could not be retrieved");
                throw new InvalidOperationException("Could not retrieve certificate, please report issue");
            }
            authCert = (BC::X509Certificate)iterator.Current;

            return CertVerifier.VerifyEnc(encCert, authCert, certs, new List<X509Crl>(0) , new List<BasicOcspResp>(0), DateTime.UtcNow);
        }

    }
}
