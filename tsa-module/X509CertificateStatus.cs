/*
 *  This file is part of eH-I.
 *  Copyright (C) 2015 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using BC = Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Security;
using System.Diagnostics;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509.Store;
using System.Collections;

namespace Egelke.EHealth.Client.Pki
{
    internal class X509CertificateStatus
    {
        private static readonly TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");

        public X509Certificate2 Certificate { get; set; }
        public X509Certificate2 Issuer { get; set; }
        public DateTime ValidationTime { get; set; }
        public CertificateList NewCertList { get; set; }
        public BasicOcspResponse NewOcspResponse { get; set; }
        public bool CheckSuspend { get; set; }
        public TimeSpan MaxDelay { get; set; }
        public TimeSpan ClockSkewness { get; set; }
        public bool OcspOnly { get; set; }

        X509Crl bestCrl = null;  
        BasicOcspResp bestOcspResp = null;
        SingleResp bestSingleOcspResp = null;
        private BC::X509Certificate certificateBC;
        private BC::X509Certificate issuerBC;
        private DateTime minTime;
        private DateTime maxTime;

        public X509CertificateStatus(X509Certificate2 Certificate, X509Certificate2 Issuer)
        {
            this.Certificate = Certificate;
            this.Issuer = Issuer;

            this.OcspOnly = false;
            this.CheckSuspend = false;
            this.MaxDelay = TimeSpan.MaxValue;
            this.ValidationTime = DateTime.UtcNow;
            this.ClockSkewness = new TimeSpan(0, 1, 0);
        }

        public X509ChainStatus Calculate(ref IList<CertificateList> certLists, ref IList<BasicOcspResponse> ocspResponses)
        {
            X509ChainStatus status = new X509ChainStatus();

            maxTime = ValidationTime + ClockSkewness;
            minTime = ValidationTime - ClockSkewness;
            certificateBC = DotNetUtilities.FromX509Certificate(Certificate);
            issuerBC = DotNetUtilities.FromX509Certificate(Issuer);

            //If no (OCSP) revocation check is allowed
            if (certificateBC.GetNonCriticalExtensionOids().Contains(OcspObjectIdentifiers.PkixOcspNocheck.Id))
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "No revocation needed for {0} because of extension", Certificate.Subject);
                status.Status = X509ChainStatusFlags.NoError;
                return status;
            }

            //Find a matching OCSP in the list
            if (ocspResponses != null)
            {
                foreach (BasicOcspResponse ocspResponse in ocspResponses)
                {
                    SelectIfBest(ocspResponse);
                }
            }
            if (SelectIfBest(NewOcspResponse))
            {
                if (!ocspResponses.Contains(NewOcspResponse, new Asn1EqualityComparer())) ocspResponses.Add(NewOcspResponse);
            }

            //Found OCSP
            if (bestSingleOcspResp != null)
            {
                //check signature
                BC::X509Certificate ocspSignerBc;
                var id = (DerTaggedObject)bestOcspResp.ResponderId.ToAsn1Object().ToAsn1Object();
                switch (id.TagNo)
                {
                    case 1:
                        X509CertStoreSelector selector = new X509CertStoreSelector();
                        selector.Subject = X509Name.GetInstance(id.GetObject());
                        IEnumerator selected = bestOcspResp.GetCertificates("Collection").GetMatches(selector).GetEnumerator();
                        if (!selected.MoveNext())
                        {
                            trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} is signed by an unknown signer", Certificate.Subject);
                            status.Status = X509ChainStatusFlags.CtlNotSignatureValid;
                            status.StatusInformation = "The OCSP is signed by a unknown certificate";
                            return status;
                        }
                        ocspSignerBc = (BC::X509Certificate)selected.Current;
                        break;
                    default:
                        trace.TraceEvent(TraceEventType.Error, 0, "OCSP response for {0} does not have a ResponderID", Certificate.Subject);
                        throw new NotSupportedException("This library only support ResponderID's by name");
                }
                if (!bestOcspResp.Verify(ocspSignerBc.GetPublicKey()))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} has an invalid signature", Certificate.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotSignatureValid;
                    status.StatusInformation = "The OCSP has an invalid signature";
                    return status;
                }

                //check the signers chain.
                X509Certificate2 ocspSigner = new X509Certificate2(ocspSignerBc.GetEncoded());
                X509Certificate2Collection ocspExtraStore = new X509Certificate2Collection();
                foreach (BC::X509Certificate ocspCert in bestOcspResp.GetCertificates("Collection").GetMatches(null))
                {
                    ocspExtraStore.Add(new X509Certificate2(ocspCert.GetEncoded()));
                }
                //check the ocsp chain at the time the OCSP was generated (time already validated during selection)
                Chain ocspChain = ocspSigner.BuildChain(bestOcspResp.ProducedAt.ToUniversalTime(), ocspExtraStore, ref certLists, ref ocspResponses);  //We assume there is not suspension for OCSP end-certificates
                if (ocspChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} has an invalid certificate chain", Certificate.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotTimeValid;
                    status.StatusInformation = "The OCSP is signed by a certificate that hasn't a valid chain";
                    return status;
                }
                foreach(ChainElement ocspChainElement in ocspChain.ChainElements)
                {
                    if (ocspChainElement.ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} has an invalid certificate {1} in the chain", Certificate.Subject, ocspChainElement.Certificate.Subject);
                        status.Status = X509ChainStatusFlags.CtlNotTimeValid;
                        status.StatusInformation = "The OCSP is signed by a certificate that hasn't a valid chain";
                        return status;
                    }
                }

                //check the signer (only the part relevant for OCSP)
                IList ocspSignerExtKeyUsage = ocspSignerBc.GetExtendedKeyUsage();
                if (!ocspSignerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.9"))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} is signed by certificate {1} that isn't allowed to sign OCSP responses", Certificate.Subject, ocspSignerBc.SubjectDN);
                    status.Status = X509ChainStatusFlags.CtlNotValidForUsage;
                    status.StatusInformation = "The OCSP is signed by a certificate that isn't allowed to sign OCSP";
                    return status;
                }

                //check if the certificate is revoked
                if (bestSingleOcspResp.GetCertStatus() != null)
                {
                    RevokedStatus revokedStatus = (RevokedStatus)bestSingleOcspResp.GetCertStatus();
                    trace.TraceEvent(TraceEventType.Verbose, 0, "OCSP response for {0} indicates that the certificate is revoked on {1}", Certificate.Subject, revokedStatus.RevocationTime);
                    if (maxTime >= revokedStatus.RevocationTime)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} indicates that the certificate is revoked on {1}, which is before the usage on {2}",
                            Certificate.Subject, revokedStatus.RevocationTime, ValidationTime);
                        status.Status = X509ChainStatusFlags.Revoked;
                        status.StatusInformation = "The OCSP response marks the certificate as revoked";
                        return status;
                    }
                }

                //check if status is still up to date
                if (CheckSuspend && bestSingleOcspResp.ThisUpdate > (maxTime + MaxDelay))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response of {1} for {0} is older then {3} at {2} and therefore certificate might been suspended at the time of use",
                        Certificate.Subject, bestSingleOcspResp.ThisUpdate, ValidationTime, MaxDelay);
                    status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                    status.StatusInformation = "The revocation information is outdated which means the certificate could have been suspended when used";
                    return status;
                }

                status.Status = X509ChainStatusFlags.NoError;
                return status;
            }
            else if (OcspOnly)
            {
                //There was a new OCSP response that didn't match
                status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                status.StatusInformation = "No matching OCSP response found";
                return status;
            }

            //No OCSP found, going for CRL
            foreach (CertificateList certList in certLists)
            {
                SelectIfBest(certList);
            }
            if (SelectIfBest(NewCertList))
            {
                if (!certLists.Contains(NewCertList, new Asn1EqualityComparer())) certLists.Add(NewCertList);
            }

            //Found CRL, validating it.
            if (bestCrl != null)
            {
                //check the signature (no need the check the issuer here)
                try
                {
                    bestCrl.Verify(issuerBC.GetPublicKey());
                }
                catch
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "CRL for {0} has an invalid signature", Certificate.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotSignatureValid;
                    status.StatusInformation = "The CRL has an invalid signature";
                    return status;
                }

                //check the signer (only the part relevant for CRL)
                if (!issuerBC.GetKeyUsage()[6])
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "CRL for {0} was signed with a certificate that isn't allowed to sign CRLs", Certificate.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotValidForUsage;
                    status.StatusInformation = "The CRL was signed with a certificate that isn't allowed to sign CRLs";
                    return status;
                }

                //check if the certificate is revoked
                X509CrlEntry crlEntry = bestCrl.GetRevokedCertificate(certificateBC.SerialNumber);
                if (crlEntry != null)
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "CRL indicates that {0} is revoked on {1}", Certificate.Subject, crlEntry.RevocationDate);
                    if (maxTime >= crlEntry.RevocationDate)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "CRL indicates that {0} is revoked on {1} which is before the usage on {2}",
                            Certificate.Subject, crlEntry.RevocationDate, ValidationTime);
                        status.Status = X509ChainStatusFlags.Revoked;
                        status.StatusInformation = "The CRL marks the certificate as revoked";
                        return status;
                    }
                }

                if (CheckSuspend)
                {
                    //We don't support checking for suspend with CRL
                    status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                    status.StatusInformation = "Suspend check not supported for CRLs";
                    return status;
                }

                status.Status = X509ChainStatusFlags.NoError;
                return status;
            }
            else
            {
                //There was a new OCSP response that didn't match
                status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                status.StatusInformation = "No matching OCSP or CRL response found";
                return status;
            }
        }

        private bool SelectIfBest(CertificateList certList)
        {
            if (certList == null)
                return false;

            bool updated = false;
            X509Crl crl = new X509Crl(certList);
            if (crl.IssuerDN.Equals(certificateBC.IssuerDN)
                && ((crl.NextUpdate != null && crl.NextUpdate.Value > minTime) || crl.ThisUpdate > minTime))
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "Found matching CRL for {0}, generated on {1}",
                   Certificate.Subject, crl.ThisUpdate);
                if (bestCrl == null)
                {
                    bestCrl = crl;
                    updated = true;
                }
                else
                {
                    //check whatever is closed to the requested time
                    TimeSpan currentDiff = ValidationTime - bestCrl.ThisUpdate;
                    TimeSpan newDiff = ValidationTime - crl.ThisUpdate;
                    if (Math.Abs(newDiff.TotalMilliseconds) < Math.Abs(currentDiff.TotalMilliseconds))
                    {
                        bestCrl = crl;
                        updated = true;
                    }
                }
            }
            return updated;
        }

        private bool SelectIfBest(BasicOcspResponse ocspResponse)
        {
            if (ocspResponse == null)
                return false;

            BasicOcspResp ocspResp = new BasicOcspResp(ocspResponse);
            IEnumerable<SingleResp> matchingSingleResps = ocspResp.Responses.Where(x => x.GetCertID().SerialNumber.Equals(certificateBC.SerialNumber) && x.GetCertID().MatchesIssuer(issuerBC)
                 && ((x.NextUpdate != null && x.NextUpdate.Value > minTime) || x.ThisUpdate > minTime));

            bool updated = false;
            foreach (SingleResp singleResp in matchingSingleResps)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "Found matching Single OCSP Response for {0}, generated on {1} (valid until {3}) with valid status = {2}",
                    Certificate.Subject, singleResp.ThisUpdate, singleResp.GetCertStatus() == null, singleResp.NextUpdate != null ? singleResp.NextUpdate.Value : DateTime.MaxValue);

                if (bestSingleOcspResp == null)
                {
                    bestOcspResp = ocspResp;
                    bestSingleOcspResp = singleResp;
                    updated = true;
                }
                else
                {
                    TimeSpan currentDiff = ValidationTime - bestSingleOcspResp.ThisUpdate;
                    TimeSpan newDiff = ValidationTime - singleResp.ThisUpdate;
                    if (Math.Abs(newDiff.TotalMilliseconds) < Math.Abs(currentDiff.TotalMilliseconds))
                    {
                        bestOcspResp = ocspResp;
                        bestSingleOcspResp = singleResp;
                        updated = true;
                    }
                }
            }
            return updated;
        }
    }
}
