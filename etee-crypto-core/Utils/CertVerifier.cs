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

using Egelke.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using Egelke.EHealth.Etee.Crypto.Status;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal class CertVerifier
    {
        private static TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        public static CertificateSecurityInformation VerifyAuth(Org.BouncyCastle.X509.X509Certificate cert, DateTime date, IX509Store certs, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, bool checkRevocation, bool checkTime)
        {
            CertificateSecurityInformation result = Verify(cert, date, certs, crls, ocsps, checkRevocation, checkTime);

            if (!cert.GetKeyUsage()[0])
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
            }

            return result;
        }

        public static CertificateSecurityInformation VerifySign(Org.BouncyCastle.X509.X509Certificate cert, DateTime date, IX509Store certs, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, bool checkRevocation, bool checkTime)
        {
            CertificateSecurityInformation result = Verify(cert, date, certs, crls, ocsps, checkRevocation, checkTime);

            if (!cert.GetKeyUsage()[1])
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
            }

            return result;
        }

        public static CertificateSecurityInformation VerifyBoth(Org.BouncyCastle.X509.X509Certificate cert, DateTime date, IX509Store certs, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, bool checkRevocation, bool checkTime)
        {
            CertificateSecurityInformation result = Verify(cert, date, certs, crls, ocsps, checkRevocation, checkTime);

            //check key usage
            int[] keyUsageIndexes = new int[] { 0, 1 };
            foreach (int i in keyUsageIndexes)
            {
                if (!cert.GetKeyUsage()[i])
                {
                    result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                    trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
                }
            }

            return result;
        }

        public static CertificateSecurityInformation VerifyEnc(Org.BouncyCastle.X509.X509Certificate encCert, Org.BouncyCastle.X509.X509Certificate authCert, DateTime date, IX509Store certs, bool checkRevocation)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();

            result.Certificate = new X509Certificate2(encCert.GetEncoded());

            //check validity
            try
            {
                encCert.CheckValidity(date);
            }
            catch (CertificateExpiredException)
            {
                result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
            }
            catch (CertificateNotYetValidException)
            {
                result.securityViolations.Add(CertSecurityViolation.NotTimeValid);
            }

            //check key usage
            int[] keyUsageIndexes = new int[] { 2, 3 };
            foreach (int i in keyUsageIndexes)
            {
                if (!encCert.GetKeyUsage()[i])
                {
                    result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                    trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag set");
                }
            }

            //check issuer/subject
            if (!encCert.IssuerDN.Equivalent(encCert.SubjectDN, false)) result.securityViolations.Add(CertSecurityViolation.HasNotPermittedNameConstraint);

            //check key size
            if (!VerifyKeySize(encCert.GetPublicKey(), EteeActiveConfig.Unseal.MinimumEncryptionKeySize.AsymmerticRecipientKey)) result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);

            //check key type
            if (!(encCert.GetPublicKey() is RsaKeyParameters)) result.securityViolations.Add(CertSecurityViolation.NotValidKeyType);

            if (authCert != null)
            {
                //check signature
                try
                {
                    encCert.Verify(authCert.GetPublicKey());
                }
                catch (InvalidKeyException)
                {
                    result.securityViolations.Add(CertSecurityViolation.NotSignatureValid);
                }

                //Validate
                result.IssuerInfo = VerifyBoth(authCert, date, certs, new List<CertificateList>(0), new List<BasicOcspResponse>(0), checkRevocation, false);
            }
            else
            {
                //We assume that we have the authCert in case it's of a 3rd person, we don't care if its or own encryption cert (we only care for the validity)
            }

            return result;
        }

        private static CertificateSecurityInformation Verify(Org.BouncyCastle.X509.X509Certificate cert, DateTime date, IX509Store certs, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, bool checkRevocation, bool checkTime)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();

            AsymmetricKeyParameter key = cert.GetPublicKey();

            //check key type
            if (!(key is RsaKeyParameters))
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidKeyType);
                trace.TraceEvent(TraceEventType.Warning, 0, "The key should be RSA but was {0}", key.GetType());
            }

            //check key size
            if (!VerifyKeySize(key, EteeActiveConfig.Unseal.MinimumSignatureKeySize))
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);
                trace.TraceEvent(TraceEventType.Warning, 0, "The key was smaller then {0}", EteeActiveConfig.Unseal.MinimumSignatureKeySize);
            }

            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            foreach (Org.BouncyCastle.X509.X509Certificate obj in certs.GetMatches(null))
            {
                extraStore.Add(new X509Certificate2(obj.GetEncoded()));
            }
            Chain chain;
            if (checkRevocation)
                chain = new X509Certificate2(cert.GetEncoded()).BuildChain(date, extraStore, ref crls, ref ocsps, checkTime ? DateTime.UtcNow : date);
            else
                chain = new X509Certificate2(cert.GetEncoded()).BuildBasicChain(date, extraStore);
                    
            CertificateSecurityInformation dest = null;
            foreach (ChainElement ce in chain.ChainElements)
            {
                if (dest == null) {
                    dest = result;
                }
                else
                {
                    dest.IssuerInfo = new CertificateSecurityInformation();
                    dest = dest.IssuerInfo;
                }

                dest.Certificate = ce.Certificate;
                foreach (X509ChainStatus status in ce.ChainElementStatus.Where(x => x.Status != X509ChainStatusFlags.NoError))
                {
                    dest.securityViolations.Add((CertSecurityViolation)Enum.Parse(typeof(CertSecurityViolation), Enum.GetName(typeof(X509ChainStatusFlags), status.Status)));
                }
            }
            if (chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.PartialChain) > 0)
            {
                result.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
            }

            trace.TraceEvent(TraceEventType.Verbose, 0, "Verified certificate {0} for date {1}", cert.SubjectDN.ToString(), date);
            return result;
        }

        private static bool VerifyKeySize(AsymmetricKeyParameter key, int minKeySize)
        {
            if (key is RsaKeyParameters)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "The key has a size of {0}", ((RsaKeyParameters)key).Modulus.BitLength);
                if (((RsaKeyParameters)key).Modulus.BitLength < minKeySize)
                {
                    return false;
                }
            }
            else if (key is DsaKeyParameters)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "The key has a size of {0}", ((DsaKeyParameters)key).Parameters.P.BitLength);
                if (((DsaKeyParameters)key).Parameters.P.BitLength < minKeySize)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
