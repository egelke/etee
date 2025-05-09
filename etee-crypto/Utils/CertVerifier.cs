/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014-2016 Egelke
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

using BC = Org.BouncyCastle.X509;
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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.Utilities.Collections;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal static class CertVerifier
    {
        //private static TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        public static byte[] GetSubjectKeyIdentifier(this Org.BouncyCastle.X509.X509Certificate cert)
        {
            Asn1OctetString ski = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
            if (ski != null)
            {
                return new SubjectKeyIdentifier(ski).GetKeyIdentifier();
            }
            else
            {
                return new SubjectKeyIdentifierStructure(cert.GetPublicKey()).GetKeyIdentifier();
            }
        }

        public static CertificateSecurityInformation Verify(this Org.BouncyCastle.X509.X509Certificate cert, DateTime date, int[] keyUsageIndexes, int minimumKeySize, IStore<BC::X509Certificate> certs, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps)
        {
            CertificateSecurityInformation result = new CertificateSecurityInformation();
            result.Certificate = new X509Certificate2(cert.GetEncoded());

            //check key size
            AsymmetricKeyParameter key = cert.GetPublicKey();
            if (!VerifyKeySize(key, minimumKeySize))
            {
                result.securityViolations.Add(CertSecurityViolation.NotValidKeySize);
                //trace.TraceEvent(TraceEventType.Warning, 0, "The key was smaller then {0}", minimumKeySize);
            }

            //check key usages
            foreach (int i in keyUsageIndexes)
            {
                if (!cert.GetKeyUsage()[i])
                {
                    result.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                    //trace.TraceEvent(TraceEventType.Warning, 0, "The key usage did not have the correct usage flag {0} set", i);
                }
            }

            //build extra store
            X509Certificate2Collection extraStore = new X509Certificate2Collection();
            foreach (BC::X509Certificate obj in certs.EnumerateMatches(null))
            {
                extraStore.Add(new X509Certificate2(obj.GetEncoded()));
            }

            CertificateSecurityInformation dest = result;
            CertificateSecurityInformation previous = null;
            Org.BouncyCastle.X509.X509Certificate issuer = cert.ValidateAndGetDerivedIssuer(certs);
            if (issuer != null)
            {
                //trace.TraceEvent(TraceEventType.Verbose, 0, "Detected eHealth variant of proxy certificate");

                //check proxy certificate, is it still valid?
                if (!cert.IsValid(date))
                {
                    dest.securityViolations.Add(CertSecurityViolation.NotTimeValid);
                    //trace.TraceEvent(TraceEventType.Warning, 0, "The proxy certificate is expired or not yet valid, {0} not between {1}-{2}", 
                    //    date, cert.NotBefore, cert.NotAfter);
                }

                //The issuer signature of the proxy certificate is already checked...

                //check issuer
                previous = dest;
                dest = new CertificateSecurityInformation();
                dest.Certificate = new X509Certificate2(issuer.GetEncoded());

                //check key size of the issuer
                key = issuer.GetPublicKey();
                if (!VerifyKeySize(key, minimumKeySize))
                {
                    dest.securityViolations.Add(CertSecurityViolation.NotValidKeySize);
                    //trace.TraceEvent(TraceEventType.Warning, 0, "The key of the issuer was smaller then {0}", minimumKeySize);
                }

                //check key usage of the issuer
                foreach (int i in new int[] { 0, 1 })
                {
                    if (!issuer.GetKeyUsage()[i])
                    {
                        dest.securityViolations.Add(CertSecurityViolation.NotValidForUsage);
                        //trace.TraceEvent(TraceEventType.Warning, 0, "The key usage of the issuer did not have the correct usage flag set");
                    }
                }
            }
            

            //check the chain
            Chain chain;
            if (crls != null || ocsps != null)
                chain = dest.Certificate.BuildChain(date, extraStore, crls, ocsps);
            else
                chain = dest.Certificate.BuildChain(date, extraStore);

            //process the chain
            foreach (ChainElement ce in chain.ChainElements)
            {
                //connect the prepared link
                if (previous != null) previous.IssuerInfo = dest;

                //update the link
                dest.Certificate = ce.Certificate;
                foreach (X509ChainStatus status in ce.ChainElementStatus.Where(x => x.Status != X509ChainStatusFlags.NoError))
                {
                    dest.securityViolations.Add((CertSecurityViolation)Enum.Parse(typeof(CertSecurityViolation), Enum.GetName(typeof(X509ChainStatusFlags), status.Status)));
                }

                //prepare the next link
                previous = dest;
                dest = new CertificateSecurityInformation();
            }

            if (chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.PartialChain) > 0)
            {
                result.securityViolations.Add(CertSecurityViolation.IssuerTrustUnknown);
            }
            

            //trace.TraceEvent(TraceEventType.Verbose, 0, "Verified certificate {0} for date {1}", cert.SubjectDN.ToString(), date);
            return result;
        }

        public static Org.BouncyCastle.X509.X509Certificate ValidateAndGetDerivedIssuer(this Org.BouncyCastle.X509.X509Certificate cert, IStore<BC::X509Certificate> issuerChains)
        {
            Org.BouncyCastle.X509.X509Certificate issuer = null;

            //does it look like a self signed?
            if (!cert.IssuerDN.Equivalent(cert.SubjectDN, false))
                return null;

            //is it a self signed?
            try
            {
                cert.Verify(cert.GetPublicKey());
                return null;
            }
            catch (InvalidKeyException)
            {
                //we have to come here
            }

            //It isn't self signed, lets see if we can find a valid issuer.
            var issuerSelector = new SignerID();
            issuerSelector.Subject = cert.IssuerDN;
            foreach (Org.BouncyCastle.X509.X509Certificate potentialIssuer in issuerChains.EnumerateMatches(issuerSelector))
            {
                try
                {
                    cert.Verify(potentialIssuer.GetPublicKey());
                }
                catch (InvalidKeyException)
                {
                    //Not the actual signer, lets try the next one
                    continue;
                }

                //Find the most recent issuer that is valid
                if (potentialIssuer.IsBetter(issuer, cert.NotBefore))
                {
                    issuer = potentialIssuer;
                }
            }
            return issuer;
        }

        public static bool IsBetter(this X509Certificate2 self, X509Certificate2 other, DateTime time)
        {
            var bcSelf = DotNetUtilities.FromX509Certificate(self);
            var bcOther = other == null ? null : DotNetUtilities.FromX509Certificate(other);

            return bcSelf.IsBetter(bcOther, time);
        }

        public static bool IsBetter(this Org.BouncyCastle.X509.X509Certificate self, Org.BouncyCastle.X509.X509Certificate other, DateTime time)
        {
            return other == null ||
                    (self.IsValid(time) && !other.IsValid(time)) ||
                    (self.IsValid(time) && other.IsValid(time) && self.NotBefore > other.NotBefore);
        }

        internal static bool VerifyKeySize(AsymmetricKeyParameter key, int minKeySize)
        {
            if (key is RsaKeyParameters)
            {
                //trace.TraceEvent(TraceEventType.Verbose, 0, "The key has a size of {0}", ((RsaKeyParameters)key).Modulus.BitLength);
                if (((RsaKeyParameters)key).Modulus.BitLength < minKeySize)
                {
                    return false;
                }
            }
            else if (key is DsaKeyParameters)
            {
                //trace.TraceEvent(TraceEventType.Verbose, 0, "The key has a size of {0}", ((DsaKeyParameters)key).Parameters.P.BitLength);
                if (((DsaKeyParameters)key).Parameters.P.BitLength < minKeySize)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
