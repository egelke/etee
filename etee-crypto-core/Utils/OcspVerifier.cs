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

using BC = Org.BouncyCastle;
using Org.BouncyCastle.Ocsp;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Math;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class OcspVerifier
    {
        private static TraceSource trace = new TraceSource("Siemens.EHealth.Etee");

        /// <summary>
        /// 
        /// </summary>
        /// <param name="basicOcspResps"></param>
        /// <param name="on"></param>
        /// <param name="cert"></param>
        /// <param name="issuer"></param>
        /// <param name="location"></param>
        /// <returns>true if an OCSP response matches, otherwise false</returns>
        public static bool Verify(IList<BasicOcspResp> basicOcspResps, DateTime on, BC::X509.X509Certificate cert, BC::X509.X509Certificate issuer, string location)
        {
            BasicOcspResp recentOcspResp = null;
            foreach (BasicOcspResp basicOcspResp in basicOcspResps)
            {
                int i = 0;
                bool found = false;
                while (!found && i < basicOcspResp.Responses.Length)
                {
                    SingleResp singleOcspPres = basicOcspResp.Responses[i++];
                    BigInteger serialNumber = cert.SerialNumber;
                    CertificateID certId = singleOcspPres.GetCertID();
                    found = certId.SerialNumber.Equals(serialNumber) && certId.MatchesIssuer(issuer);
                }

                if (found)
                {
                    //check if the new OCSP response is more recent than the previous one
                    if (recentOcspResp == null || recentOcspResp.ProducedAt < basicOcspResp.ProducedAt)
                    {
                        recentOcspResp = basicOcspResp;
                    }
                }
            }

            if (recentOcspResp == null) return false;

            Verify(recentOcspResp, on, cert, issuer, location);
            return true;
        }

        public static void Verify(BasicOcspResp basicOcspResp, DateTime on, BC::X509.X509Certificate cert, BC::X509.X509Certificate issuer, string location)
        {
            BC::X509.X509Certificate bcOcspSigner = null;

            //Verify the certificate chain of the OCSP response
            ICollection ocspSignerCerts = basicOcspResp.GetCertificates("COLLECTION").GetMatches(null);

            X509Certificate2 ocspSigner = null;
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = on;
            foreach (BC::X509.X509Certificate ocspSignerCert in ocspSignerCerts)
            {
                if (ocspSigner == null)
                {
                    bcOcspSigner = ocspSignerCert;
                    ocspSigner = new X509Certificate2(ocspSignerCert.GetEncoded()); //lets assume perfect order (for now)
                }
                chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(ocspSignerCert.GetEncoded()));
            }
            chain.Build(ocspSigner);

            if ((chain.ChainStatus.Length == 1 && chain.ChainStatus[0].Status != X509ChainStatusFlags.NoError)
                || chain.ChainStatus.Length > 1)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved OCSP {0} has an invalid signer", location);
                throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " did not result in a valid OCSP response");
            }

            //check if the ocspSinger may sign an OCSP response
            IList ocspSignerExtKeyUsage = bcOcspSigner.GetExtendedKeyUsage();
            if (!ocspSignerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.9"))
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved OCSP {0} was not issued by a certificate that allows it", location);
                throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " did not result in a valid OCSP response");
            }


            //check the signature
            if (!basicOcspResp.Verify(DotNetUtilities.GetRsaPublicKey((RSA)ocspSigner.PublicKey.Key)))
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved OCSP {0} has an invalid signature", location);
                throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " did not result in a valid OCSP response");
            }

            //check it time with a 5 minute clock-skewness 
            if (on.AddMinutes(-5.0) > basicOcspResp.ProducedAt)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved OCSP {0} has an invalid time", location);
                throw new InvalidOperationException("The OCSP response of the certificate " + cert.SubjectDN.ToString() + " is not yet valid on the time of creation");
            }

            //check the status of the certificate
            foreach (SingleResp singleOcspPres in basicOcspResp.Responses)
            {
                BigInteger serialNumber = cert.SerialNumber;
                CertificateID certId = singleOcspPres.GetCertID();
                if (certId.SerialNumber.Equals(serialNumber) && certId.MatchesIssuer(issuer)
                    && singleOcspPres.GetCertStatus() != null)
                {
                    RevokedStatus status = (RevokedStatus)singleOcspPres.GetCertStatus();

                    trace.TraceEvent(TraceEventType.Warning, 0, "Retrieved OCSP {0} indicates cert is expired on {1}", location, status.RevocationTime);
                    throw new InvalidOperationException("The certificate " + cert.SubjectDN.ToString() + " is revoked");
                }
            }
        }
    }
}
