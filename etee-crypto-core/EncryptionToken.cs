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
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using BC = Org.BouncyCastle.X509;
using Org.BouncyCastle.Cms;
using System.IO;
using Siemens.EHealth.Etee.Crypto.Utils;
using System.Security.Cryptography;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Security;
using System.Collections;
using Siemens.EHealth.Etee.Crypto.Decrypt;
using System.Diagnostics;

namespace Siemens.EHealth.Etee.Crypto
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
        private TraceSource trace = new TraceSource("Siemens.EHealth.Etee");

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
                    content = StreamUtils.ReadFully(raw.SignedContent.Read());
                }
                return content;
            }
        }

        /// <summary>
        /// Verifies if the ETK is still valid and can be trusted.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This method checks if the ETK is issued by a trusted party.  Tust means
        /// the root certificate is trusted by the computer it is running on and all
        /// validation checks, including revocation, are successful.  Root
        /// certificates are trusted by the computer if present in the 
        /// <see cref="StoreName.Root"/> store.
        /// </para>
        /// <para>
        /// <strong>The method does NOT verify that the ETK is issued by eHealth</strong>,
        /// it only verifies the issuer is who he claims to be.  It is the caller of this method's 
        /// responsablity to check if this specific issuer (or sender) is trusted for issuing ETKs or not.
        /// Use the <see cref="EtkSecurityInformation.Sender"/> property of the return value to get the certificate of 
        /// the issuer and check the subject name or any other attribute to determine who is the issuer/sender.
        /// </para>
        /// </remarks>
        /// <returns>Detailed information about the verification</returns>
        public EtkSecurityInformation Verify()
        {
            trace.TraceEvent(TraceEventType.Information, 0, "Verifying ETK: {0}", ToBCCertificate().SubjectDN.ToString());

            BC::X509Certificate encCert;
            BC::X509Certificate authCert = null;
            EtkSecurityInformation result = new EtkSecurityInformation();

            //Get encryption cert
            encCert = ToBCCertificate();

            //Get authentication cert
            IX509Store certs = raw.GetCertificates("COLLECTION");
            IX509Store crls = raw.GetCrls("COLLECTION");
            SignerID authCertSelector = new SignerID();
            authCertSelector.Subject = encCert.IssuerDN;
            ICollection authCertMatch = certs.GetMatches(authCertSelector);
            if (authCertMatch.Count == 1)
            {
                IEnumerator iterator = authCertMatch.GetEnumerator();
                if (!iterator.MoveNext())
                {
                    trace.TraceEvent(TraceEventType.Error, 0, "Certificarte present but could not be retrieved");
                    throw new InvalidOperationException("Could not retrieve certificate, please report issue");
                }
                authCert = (BC::X509Certificate)iterator.Current;
            }

            //Verify message & get etk certificate
            result.Signature = Verifier.Verify(certs, crls, raw.GetSignerInfos(), null, false, false);
            result.TokenInformation = Verifier.Verify(encCert, authCert);

            return result;
        }

    }
}
