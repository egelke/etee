/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
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

using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using BC=Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Security;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509.Extension;
using System.Net;
using System.IO;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.X509.Store;
using System.Diagnostics;

namespace Egelke.EHealth.Client.Pki
{
    public static class X509CertificateHelper
    {
        private static TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");

        private static readonly TimeSpan ClockSkewness = new TimeSpan(0, 5, 0);

        private static CertificateList RetreiveCrl(BC::X509Certificate cert)
        {
            Asn1OctetString crlDPsBytes = cert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
            if (crlDPsBytes != null)
            {
                CrlDistPoint crlDPs = CrlDistPoint.GetInstance(X509ExtensionUtilities.FromExtensionValue(crlDPsBytes));
                foreach (DistributionPoint dp in crlDPs.GetDistributionPoints())
                {
                    DistributionPointName dpn = dp.DistributionPointName;
                    if (dpn != null && dpn.PointType == DistributionPointName.FullName)
                    {
                        GeneralName[] genNames = GeneralNames.GetInstance(dpn.Name).GetNames();
                        foreach (GeneralName genName in genNames)
                        {
                            if (genName.TagNo == GeneralName.UniformResourceIdentifier)
                            {
                                //Found a CRL URL, lets get it.
                                string location = DerIA5String.GetInstance(genName.Name).GetString();
                                Uri locationUri;

                                try
                                {
                                    locationUri = new Uri(location);
                                }
                                catch
                                {
                                    return null;
                                }

                                if (locationUri.Scheme != "http")
                                    return null;

                                //Make the Web request
                                trace.TraceEvent(TraceEventType.Information, 0, "retrieving CRL for {0} from {1}", cert.SubjectDN, location);
                                WebRequest crlRequest = WebRequest.Create(locationUri);
                                WebResponse crlResponse = crlRequest.GetResponse();

                                //Parse the result
                                using (crlResponse)
                                {
                                    Asn1Sequence crlAns1 = (Asn1Sequence)Asn1Sequence.FromStream(crlResponse.GetResponseStream());
                                    trace.TraceData(TraceEventType.Verbose, 0, "retrieved CRL", location, Convert.ToBase64String(crlAns1.GetEncoded()));
                                    return CertificateList.GetInstance(crlAns1);
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }

        private static BasicOcspResponse RetreiveOcsps(BC::X509Certificate cert, BC::X509Certificate issuer)
        {
            Asn1OctetString ocspDPsBytes = cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
            if (ocspDPsBytes != null)
            {
                AuthorityInformationAccess ocspAki = AuthorityInformationAccess.GetInstance(X509ExtensionUtilities.FromExtensionValue(ocspDPsBytes));
                foreach (AccessDescription ad in ocspAki.GetAccessDescriptions())
                {
                    if (AccessDescription.IdADOcsp.Equals(ad.AccessMethod)
                        && ad.AccessLocation.TagNo == GeneralName.UniformResourceIdentifier)
                    {
                        //Found an OCSP URL, lets call it.
                        string location = DerIA5String.GetInstance(ad.AccessLocation.Name).GetString();
                        Uri locationUri;

                        try
                        {
                            locationUri = new Uri(location);
                        }
                        catch
                        {
                            return null;
                        }

                        if (locationUri.Scheme != "http")
                            return null;

                        //Prepare the request
                        OcspReqGenerator ocspReqGen = new OcspReqGenerator();
                        ocspReqGen.AddRequest(new CertificateID(CertificateID.HashSha1, issuer, cert.SerialNumber));

                        //Make the request & sending it.
                        OcspReq ocspReq = ocspReqGen.Generate();
                        WebRequest ocspWebReq = WebRequest.Create(locationUri);
                        ocspWebReq.Method = "POST";
                        ocspWebReq.ContentType = "application/ocsp-request";
                        Stream ocspWebReqStream = ocspWebReq.GetRequestStream();
                        ocspWebReqStream.Write(ocspReq.GetEncoded(), 0, ocspReq.GetEncoded().Length);
                        trace.TraceEvent(TraceEventType.Information, 0, "retrieving OCSP for {0} from {1}", cert.SubjectDN, location);
                        WebResponse ocspWebResp = ocspWebReq.GetResponse();

                        //Get the response
                        OcspResponse ocspResponse;
                        using (ocspWebResp)
                        {
                            ocspResponse = OcspResponse.GetInstance(new Asn1InputStream(ocspWebResp.GetResponseStream()).ReadObject());
                            trace.TraceData(TraceEventType.Verbose, 0, "retrieved OCSP-response", location, Convert.ToBase64String(ocspResponse.GetEncoded()));
                        }

                        //Check the responder status
                        var ocspResp = new OcspResp(ocspResponse);
                        if (ocspResp.Status == 0)
                        {
                            return BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(ocspResponse.ResponseBytes.Response.GetOctets()));
                        } 
                        else
                        {
                            return null;
                        }
                    }
                }
            }
            return null;
        }

        public static X509ChainStatus CheckRevocation(this X509Certificate2 cert, X509Certificate2 issuer, DateTime validationTime, ref IList<CertificateList> certLists, ref IList<BasicOcspResponse> ocspResponses, bool checkSuspend, TimeSpan maxDelay)
        {
            X509ChainStatus status = new X509ChainStatus();
            status.Status = X509ChainStatusFlags.NoError;

            BC::X509Certificate certBc = DotNetUtilities.FromX509Certificate(cert);
            BC::X509Certificate issuerBc = DotNetUtilities.FromX509Certificate(issuer);

            //If no (OCSP) revocation check is allowed
            if (certBc.GetNonCriticalExtensionOids().Contains(OcspObjectIdentifiers.PkixOcspNocheck.Id))
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "No revocation needed for {0} because of extension", cert.Subject);
                return status;
            }

            //Find the OCSP in the list
            BasicOcspResp bestOcspResp = null;
            SingleResp bestSingleOcspResp = null;
            foreach (BasicOcspResponse ocspResponse in ocspResponses)
            {
               BasicOcspResp ocspResp = new BasicOcspResp(ocspResponse);
               //producedAt vs thisUpdate seem to be the same
               //TODO::verify with expired certificate

               IEnumerable<SingleResp> matchingSingleResps = ocspResp.Responses.Where(x => x.GetCertID().SerialNumber.Equals(certBc.SerialNumber) && x.GetCertID().MatchesIssuer(issuerBc) 
                    && ((x.NextUpdate != null && x.NextUpdate.Value > validationTime) || x.ThisUpdate > validationTime));

               foreach (SingleResp singleResp in matchingSingleResps)
               {
                   trace.TraceEvent(TraceEventType.Verbose, 0, "Found matching Single OCSP Response for {0}, generated on {1} with valid status = {2}", 
                       cert.Subject, singleResp.ThisUpdate, singleResp.GetCertStatus() == null);
                   if (bestSingleOcspResp == null)
                    {
                        bestOcspResp = ocspResp;
                        bestSingleOcspResp = singleResp;
                    }
                    else
                    {
                        //check whatever is closed to the requested time
                        TimeSpan currentDiff = validationTime - bestSingleOcspResp.ThisUpdate;
                        TimeSpan newDiff = validationTime - singleResp.ThisUpdate;
                        if (newDiff.Duration() < currentDiff.Duration())
                        {
                            bestOcspResp = ocspResp;
                            bestSingleOcspResp = singleResp;
                        }
                    }
               }
            }

            //No OCSP found, looking for CRL in the provided list.
            X509Crl bestCrl = null;
            foreach (CertificateList certList in certLists)
            {
                X509Crl crl = new X509Crl(certList);
                if (crl.IssuerDN.Equals(certBc.IssuerDN)
                    && ((crl.NextUpdate != null && crl.NextUpdate.Value > validationTime) || crl.ThisUpdate > validationTime))
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Found matching CRL for {0}, generated on {1}",
                       cert.Subject, crl.ThisUpdate);
                    if (bestCrl == null)
                    {
                        bestCrl = crl;
                    }
                    else
                    {
                        //check whatever is closed to the requested time
                        TimeSpan currentDiff = validationTime - bestCrl.ThisUpdate;
                        TimeSpan newDiff = validationTime - crl.ThisUpdate;
                        if (newDiff.Duration() < currentDiff.Duration()) bestCrl = crl;
                    }
                }
            }

            //Found neither OCSP or CRL, retrieving OCSP
            if (bestOcspResp == null && bestCrl == null)
            {
                BasicOcspResponse ocspResponse = RetreiveOcsps(certBc, issuerBc);
                if (ocspResponse != null)
                {
                    ocspResponses.Add(ocspResponse);

                    //we know there is only one, so it is easier to extract
                    bestOcspResp = new BasicOcspResp(ocspResponse);
                    bestSingleOcspResp = bestOcspResp.Responses[0];
                }
            }

            //No OCSP to retrieve, retrieving CRL, crl can still be useful
            if (bestOcspResp == null && bestCrl == null)
            {
                CertificateList crl = RetreiveCrl(certBc);
                if (crl != null)
                {
                    bestCrl = new X509Crl(crl);
                    certLists.Add(crl);

                }
            }
            

            //Didn't find any CRL or OCSP anywhere
            if (bestOcspResp == null && bestCrl == null)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "No revocation information found for {0}", cert.Subject);
                status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                status.StatusInformation = "No revocation information available for the certificate";
                return status;
            }

            //found OCSP, validating it
            if (bestSingleOcspResp != null)
            {
                //check signature
                BC::X509Certificate ocspSignerBc;
                var id = (DerTaggedObject) bestOcspResp.ResponderId.ToAsn1Object().ToAsn1Object();
                switch (id.TagNo)
                {
                    case 1:
                        X509CertStoreSelector selector = new X509CertStoreSelector();
                        selector.Subject = X509Name.GetInstance(id.GetObject());
                        IEnumerator selected = bestOcspResp.GetCertificates("Collection").GetMatches(selector).GetEnumerator();
                        if (!selected.MoveNext())
                        {
                            trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} is signed by an unknown signer", cert.Subject);
                            status.Status = X509ChainStatusFlags.CtlNotSignatureValid;
                            status.StatusInformation = "The OCSP is signed by a unknown certificate";
                            return status;
                        }
                        ocspSignerBc = (BC::X509Certificate)selected.Current;
                        break;
                    default:
                        trace.TraceEvent(TraceEventType.Error, 0, "OCSP response for {0} does not have a ResponderID", cert.Subject);
                        throw new NotSupportedException("This library only support ResponderID's by name");
                }
                if (!bestOcspResp.Verify(ocspSignerBc.GetPublicKey()))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} has an invalid signature", cert.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotSignatureValid;
                    status.StatusInformation = "The OCSP has an invalid signature";
                    return status;
                }

                //check the signers chain.
                X509Certificate2 ocspSigner = new X509Certificate2(ocspSignerBc.GetEncoded());
                X509Certificate2Collection ocspExtraStore = new X509Certificate2Collection();
                foreach(BC::X509Certificate ocspCert in bestOcspResp.GetCertificates("Collection").GetMatches(null))
                {
                    ocspExtraStore.Add(new X509Certificate2(ocspCert.GetEncoded()));
                }
                
                DateTime now = DateTime.UtcNow;
                //allow for some clock skewness
                DateTime signingTime = bestOcspResp.ProducedAt > now && (bestOcspResp.ProducedAt - ClockSkewness) < now  ? now : bestOcspResp.ProducedAt;
                //The signing time of ocsp responses can be trusted if it is later then the provided validation time (since we assume there is not suspension for OCSP responses)
                DateTime trustedTime = signingTime > validationTime ? signingTime : validationTime;
                Chain ocspChain = ocspSigner.BuildChain(signingTime, ocspExtraStore, ref certLists, ref ocspResponses, trustedTime);  //again we assume there is not suspension for OCSP responses
                if (ocspChain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} has an invalid certificate chain", cert.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotTimeValid;
                    status.StatusInformation = "The OCSP is signed by a certificate that hasn't a valid chain";
                    return status;
                }
                foreach(ChainElement ocspChainElement in ocspChain.ChainElements)
                {
                    if (ocspChainElement.ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} has an invalid certificate {1} in the chain", cert.Subject, ocspChainElement.Certificate.Subject);
                        status.Status = X509ChainStatusFlags.CtlNotTimeValid;
                        status.StatusInformation = "The OCSP is signed by a certificate that hasn't a valid chain";
                        return status;
                    }
                }

                //check the signer (only the part relevant for OCSP)
                IList ocspSignerExtKeyUsage = ocspSignerBc.GetExtendedKeyUsage();
                if (!ocspSignerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.9"))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} is signed by certificate {1} that isn't allowed to sign OCSP responses", cert.Subject, ocspSignerBc.SubjectDN);
                    status.Status = X509ChainStatusFlags.CtlNotValidForUsage;
                    status.StatusInformation = "The OCSP is signed by a certificate that isn't allowed to sign OCSP";
                    return status;
                }

                //check if the certificate is revoked
                if (bestSingleOcspResp.GetCertStatus() != null)
                {
                    RevokedStatus revokedStatus = (RevokedStatus) bestSingleOcspResp.GetCertStatus();
                    trace.TraceEvent(TraceEventType.Verbose, 0, "OCSP response for {0} indicates that the certificate is revoked on {1}", cert.Subject, revokedStatus.RevocationTime);
                    if (validationTime >= revokedStatus.RevocationTime)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response for {0} indicates that the certificate is revoked on {1}, which is before the usage on {2}", 
                            cert.Subject, revokedStatus.RevocationTime, validationTime);
                        status.Status = X509ChainStatusFlags.Revoked;
                        status.StatusInformation = "The OCSP response marks the certificate as revoked";
                        return status;
                    }
                }

                //check if status is still up to date
                if (checkSuspend && bestSingleOcspResp.ThisUpdate > (validationTime + maxDelay))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "OCSP response of {1} for {0} is older then {3} at {2} and therefore certificate might been suspended at the time of use",
                        cert.Subject, bestSingleOcspResp.ThisUpdate, validationTime, maxDelay);
                    status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                    status.StatusInformation = "The revocation information is outdated which means the certificate could have been suspended when used";
                    return status;
                }
            }

            //Found CRL, validating it.
            if (bestCrl != null)
            {
                //check the signature (no need the check the issuer here)
                try
                {
                    bestCrl.Verify(issuerBc.GetPublicKey());
                }
                catch
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "CRL for {0} has an invalid signature", cert.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotSignatureValid;
                    status.StatusInformation = "The CRL has an invalid signature";
                    return status;
                }

                //check the signer (only the part relevant for CRL)
                if (!issuerBc.GetKeyUsage()[6])
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "CRL for {0} was signed with a certificate that isn't allowed to sign CRLs", cert.Subject);
                    status.Status = X509ChainStatusFlags.CtlNotValidForUsage;
                    status.StatusInformation = "The CRL was signed with a certificate that isn't allowed to sign CRLs";
                    return status;
                }

                //check if the certificate is revoked
                X509CrlEntry crlEntry = bestCrl.GetRevokedCertificate(certBc.SerialNumber);
                if (crlEntry != null)
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "CRL indicates that {0} is revoked on {1}", cert.Subject, crlEntry.RevocationDate);
                    if (validationTime >= crlEntry.RevocationDate)
                    {
                        trace.TraceEvent(TraceEventType.Warning, 0, "CRL indicates that {0} is revoked on {1} which is before the usage on {2}",
                            cert.Subject, crlEntry.RevocationDate, validationTime);
                        status.Status = X509ChainStatusFlags.Revoked;
                        status.StatusInformation = "The CRL marks the certificate as revoked";
                        return status;
                    }
                }

                //check if status is still up to date
                if (checkSuspend && bestCrl.ThisUpdate > (validationTime + maxDelay))
                {
                    trace.TraceEvent(TraceEventType.Warning, 0, "CRL from {1} for {0} is older then {2} on {3} and therefore the certificate might been suspended at the time of use",
                        cert.Subject, bestCrl.ThisUpdate, maxDelay, validationTime);
                    status.Status = X509ChainStatusFlags.RevocationStatusUnknown;
                    status.StatusInformation = "The revocation information is outdated which means the certificate could have been suspended when used";
                    return status;
                }
            }

            return status;
        }

        public static Chain BuildBasicChain(this X509Certificate2 cert, DateTime signingTime, X509Certificate2Collection extraStore)
        {
            //create the X509 chain
            X509Chain x509Chain = new X509Chain();
            if (extraStore != null) x509Chain.ChainPolicy.ExtraStore.AddRange(extraStore);
            x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            x509Chain.ChainPolicy.VerificationTime = signingTime;
            x509Chain.Build(cert);

            //create the chain using the information from the X509 Chain
            Chain chain = new Chain();
            chain.ChainStatus = new List<X509ChainStatus>();
            if (trace.Switch.ShouldTrace(TraceEventType.Information))
            {
                foreach (var status in x509Chain.ChainStatus)
                {
                    trace.TraceEvent(status.Status != X509ChainStatusFlags.NoError ? TraceEventType.Warning : TraceEventType.Information, 0,
                        "The certificate {0} has a status {1}: {2}", cert.Subject, status.Status, status.StatusInformation);
                }
            }
            chain.ChainStatus.AddRange(x509Chain.ChainStatus);
            
            chain.ChainElements = new List<ChainElement>();
            X509ChainElementEnumerator x509Elements = x509Chain.ChainElements.GetEnumerator();
            while (x509Elements.MoveNext())
            {
                if (trace.Switch.ShouldTrace(TraceEventType.Information))
                {
                    foreach (var status in x509Elements.Current.ChainElementStatus)
                    {
                        trace.TraceEvent(status.Status != X509ChainStatusFlags.NoError ? TraceEventType.Warning : TraceEventType.Information, 0,
                            "The certificate {0} has a status {1}: {2}", x509Elements.Current.Certificate.Subject, status.Status, status.StatusInformation);
                    }
                }
                chain.ChainElements.Add(new ChainElement(x509Elements.Current));
            }

            return chain;
        }

        public static Chain BuildChain(this X509Certificate2 cert, DateTime signingTime, X509Certificate2Collection extraStore, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps)
        {
            return cert.BuildChain(signingTime, extraStore, ref crls, ref ocsps, signingTime);
        }

        public static Chain BuildChain(this X509Certificate2 cert, DateTime signingTime, X509Certificate2Collection extraStore, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps, DateTime trustedTime)
        {
            return cert.BuildChain(signingTime, extraStore, ref crls, ref ocsps, trustedTime, false, new TimeSpan(0, 5, 0));
        }

        public static Chain BuildChain(this X509Certificate2 cert, DateTime signingTime, X509Certificate2Collection extraStore, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps, DateTime trustedTime, bool checkHistoricalSuspend, TimeSpan maxDelay)
        {
            if (signingTime > trustedTime)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "The signing time {1} is newer then the trusted time {2} for {0}", cert.Subject, signingTime, trustedTime);
                throw new ArgumentException("The trusted time must be greater or equal then the signing time", "trustedTime");
            }

            Chain chain = cert.BuildBasicChain(signingTime, extraStore);
            List<ChainElement>.Enumerator elements = chain.ChainElements.GetEnumerator();
            if (elements.MoveNext())
            {
                ChainElement currentElement = elements.Current;
                while (elements.MoveNext())
                {
                    ChainElement issuerElement = elements.Current;

                    //Add revocation status info that is manually retrieved.
                    X509ChainStatus status = currentElement.Certificate.CheckRevocation(issuerElement.Certificate, trustedTime, ref crls, ref ocsps, checkHistoricalSuspend, maxDelay);
                    if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        AddErrorStatus(chain.ChainStatus, status);
                        AddErrorStatus(currentElement.ChainElementStatus, status);
                    }
                    if (signingTime != trustedTime && checkHistoricalSuspend)
                    {
                        status = currentElement.Certificate.CheckRevocation(issuerElement.Certificate, signingTime, ref crls, ref ocsps, checkHistoricalSuspend, maxDelay);
                        if (status.Status != X509ChainStatusFlags.NoError)
                        {
                            AddErrorStatus(chain.ChainStatus, status);
                            AddErrorStatus(currentElement.ChainElementStatus, status);
                        }
                    }
                    currentElement = issuerElement;
                }
            }
            return chain;
        }

        internal static void AddErrorStatus(List<X509ChainStatus> statusList, X509ChainStatus extraStatus)
        {
            foreach (X509ChainStatus noErrorStatus in statusList.Where(x => x.Status == X509ChainStatusFlags.NoError))
            {
                statusList.Remove(noErrorStatus);
            }
            if (statusList.Count(x => x.Status == extraStatus.Status) == 0) statusList.Add(extraStatus);
        }
    }
}
