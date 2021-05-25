/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014-2021 Egelke BVBA
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using BC = Org.BouncyCastle;
using BCX = Org.BouncyCastle.X509;
using BCA = Org.BouncyCastle.Asn1;
using BCAX = Org.BouncyCastle.Asn1.X509;
using BCAO = Org.BouncyCastle.Asn1.Ocsp;
using BCS = Org.BouncyCastle.X509.Store;
using System.Diagnostics;
using System.Runtime.InteropServices;
using BCO = Org.BouncyCastle.Ocsp;
using System.Net;
using System.IO;
using Org.BouncyCastle.Security;
using System.Threading.Tasks;
using System.Collections;
using System.Security.Cryptography;

namespace Egelke.EHealth.Client.Pki
{

    internal class ValueWithRef<T, U>
    {
        public T Value { get; }

        public U Reference { get; }

        public ValueWithRef(T value, U reference)
        {
            this.Value = value;
            this.Reference = reference;
        }
    }

    /// <summary>
    /// Excention class for X509Certificate2.
    /// </summary>
    public static class X509CertificateHelper
    {
        //private const int CRYPT_E_EXISTS = unchecked((int)0x80092005);

        private static readonly TimeSpan ClockSkewness = new TimeSpan(0, 5, 0);
        private static readonly TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");

        /// <summary>
        /// Wrapper of the X509Chain, just for compatbility
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <returns></returns>
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore)
        {
            DateTime now = DateTime.UtcNow;
            if (validationTime > (now + ClockSkewness))
            {
                throw new ArgumentException("validation can't occur in the future", "validationTime");
            }

            X509Chain x509Chain = new X509Chain();
            if (extraStore != null) x509Chain.ChainPolicy.ExtraStore.AddRange(extraStore);
            x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            x509Chain.ChainPolicy.VerificationTime = validationTime;
            x509Chain.Build(cert);

            Chain chain = new Chain();
            foreach (var status in x509Chain.ChainStatus)
            {
                trace.TraceEvent(status.Status != X509ChainStatusFlags.NoError ? TraceEventType.Warning : TraceEventType.Information, 0,
                    "The certificate chain for {0} has a status {1}: {2}", cert.Subject, status.Status, status.StatusInformation);
                chain.ChainStatus.Add(status);
            }

            foreach (X509ChainElement x509Element in x509Chain.ChainElements)
            {
                chain.ChainElements.Add(new ChainElement(x509Element));
            }

            return chain;
        }

        /// <summary>
        /// Build a chain for the certificates and verifies the revocation (own implementation)
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <param name="crls">Already known crl's, newly retrieved CRL's will be added here</param>
        /// <param name="ocsps">Already konwn ocsp's, newly retreived OCSP's will be added here</param>
        /// <returns>The chain with all the information about validity</returns>
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<BCAX.CertificateList> crls, IList<BCAO.BasicOcspResponse> ocsps)
        {
            Chain chain = cert.BuildChain(validationTime, extraStore);

            if (cert.IsOcspNoCheck())
                return chain; //nothing to do

            for (int i = 0; i < (chain.ChainElements.Count - 1); i++)
            {
                X509Certificate2 nextCert = chain.ChainElements[i].Certificate;
                X509Certificate2 nextIssuer = chain.ChainElements[i + 1].Certificate;

                try
                {
                    //try OCSP
                    BCAO.BasicOcspResponse ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                    if (ocspResponse == null)
                    {
                        //try to fetch a new one
                        BCAO.OcspResponse ocspMsg = nextCert.GetOcspResponse(nextIssuer);
                        if (ocspMsg != null)
                        {
                            //new one fetched, try again
                            ocspResponse = BCAO.BasicOcspResponse.GetInstance(BCA.Asn1Object.FromByteArray(ocspMsg.ResponseBytes.Response.GetOctets()));
                            ocsps.Add(ocspResponse);
                            ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                        }
                    }

                    //TODO::ignore OCSP retreival errors and try CRL ;-)
                    if (ocspResponse == null)
                    {
                        //try CRL
                        BCAX.CertificateList crl = nextCert.Verify(nextIssuer, validationTime, crls);
                        if (crl == null)
                        {
                            //try to fetch a new one
                            crl = nextCert.GetCertificateList();
                            if (crl != null)
                            {
                                //new one fetched, try again
                                crls.Add(crl);
                                crl = nextCert.Verify(nextIssuer, validationTime, crls);
                            }
                        }
                    }
                }
                catch (RevocationException<BCAO.BasicOcspResponse>)
                {
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.Revoked, "The certificate has been revoked");
                }
                catch
                {
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.RevocationStatusUnknown, "Invalid OCSP/CRL found");
                }
            }
            return chain;
        }

        /// <summary>
        /// Build a chain for the certificates and verifies the revocation (own implementation)
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <param name="crls">Already known crl's, newly retrieved CRL's will be added here</param>
        /// <param name="ocsps">Already konwn ocsp's, newly retreived OCSP's will be added here</param>
        /// <returns>The chain with all the information about validity</returns>
        public static async Task<Chain> BuildChainAsync(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<BCAX.CertificateList> crls, IList<BCAO.BasicOcspResponse> ocsps)
        {
            Chain chain = cert.BuildChain(validationTime, extraStore);

            if (cert.IsOcspNoCheck())
                return chain; //nothing to do

            for (int i = 0; i < (chain.ChainElements.Count - 1); i++)
            {
                X509Certificate2 nextCert = chain.ChainElements[i].Certificate;
                X509Certificate2 nextIssuer = chain.ChainElements[i + 1].Certificate;

                try
                {
                    //try OCSP
                    BCAO.BasicOcspResponse ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                    if (ocspResponse == null)
                    {
                        //try to fetch a new one
                        BCAO.OcspResponse ocspMsg = await nextCert.GetOcspResponseAsync(nextIssuer);
                        if (ocspMsg != null)
                        {
                            //new one fetched, try again
                            ocspResponse = BCAO.BasicOcspResponse.GetInstance(BCA.Asn1Object.FromByteArray(ocspMsg.ResponseBytes.Response.GetOctets()));
                            ocsps.Add(ocspResponse);
                            ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                        }
                    }

                    //TODO::ignore OCSP retreival errors and try CRL ;-)
                    if (ocspResponse == null)
                    {
                        //try CRL
                        BCAX.CertificateList crl = nextCert.Verify(nextIssuer, validationTime, crls);
                        if (crl == null)
                        {
                            //try to fetch a new one
                            crl = await nextCert.GetCertificateListAsync();
                            if (crl != null)
                            {
                                //new one fetched, try again
                                crls.Add(crl);
                                crl = nextCert.Verify(nextIssuer, validationTime, crls);
                            }
                        }
                    }
                }
                catch (RevocationException<BCAO.BasicOcspResponse>)
                {
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.Revoked, "The certificate has been revoked");
                }
                catch
                {
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.RevocationStatusUnknown, "Invalid OCSP/CRL found");
                }
            }
            return chain;
        }
        /// <summary>
        /// Is the OCSP NoCheck extention present?
        /// </summary>
        /// <param name="certificate">The cert to check</param>
        /// <returns><c>true</c>When present, <c>false</c>otherwise</returns>
        public static bool IsOcspNoCheck(this X509Certificate2 certificate)
        {
            return certificate.Extensions[BCAO.OcspObjectIdentifiers.PkixOcspNocheck.Id] != null;
        }

        /// <summary>
        /// Validates the cert with the provided ocsp responses.
        /// </summary>
        /// <param name="certificate">The cert to validate</param>
        /// <param name="issuer">The issuer of the cert to validate</param>
        /// <param name="validationTime">The time on which the cert was needed to validated</param>
        /// <param name="ocspResponses">The list of ocsp responses to use</param>
        /// <returns>The OCSP response that was used, <c>null</c> if none was found</returns>
        /// <exception cref="RevocationException{T}">When the certificate was revoked on the provided time</exception>
        /// <exception cref="RevocationUnknownException">When the certificate (or the OCSP) can't be validated</exception>
        public static BCAO.BasicOcspResponse Verify(this X509Certificate2 certificate, X509Certificate2 issuer, DateTime validationTime, IList<BCAO.BasicOcspResponse> ocspResponses)
        {
            DateTime minTime = validationTime - ClockSkewness;
            DateTime maxTime = validationTime + ClockSkewness;
            BCX.X509Certificate certificateBC = DotNetUtilities.FromX509Certificate(certificate);
            BCX.X509Certificate issuerBC = DotNetUtilities.FromX509Certificate(issuer);

            ValueWithRef<BCO.SingleResp, ValueWithRef<BCO.BasicOcspResp, BCAO.BasicOcspResponse>> singleOcspRespLeaf = ocspResponses
                .Select((rsp) => new ValueWithRef<BCO.BasicOcspResp, BCAO.BasicOcspResponse>(new BCO.BasicOcspResp(rsp), rsp)) //convert, but keep the original
                .SelectMany((r) => r.Value.Responses.Select(sr => new ValueWithRef<BCO.SingleResp, ValueWithRef<BCO.BasicOcspResp, BCAO.BasicOcspResponse>>(sr, r))) //get the single respononses, but keep the parent
                .Where((sr) => sr.Value.GetCertID().SerialNumber.Equals(certificateBC.SerialNumber) && sr.Value.GetCertID().MatchesIssuer(issuerBC)) //is it for this cert?
                .Where((sr) => sr.Value.ThisUpdate >= minTime || (sr.Value.NextUpdate != null && sr.Value.NextUpdate.Value >= minTime)) //was it issued on time?
                .OrderByDescending((sr) => sr.Value.ThisUpdate) //newest first
                .FirstOrDefault();

            if (singleOcspRespLeaf == null)
                return null;

            BCO.SingleResp singleOcspResp = singleOcspRespLeaf.Value;
            BCO.BasicOcspResp basicOcspResp = singleOcspRespLeaf.Reference.Value;
            BCAO.BasicOcspResponse basicOcspResponse = singleOcspRespLeaf.Reference.Reference;

            //get the signer name
            BCX.X509Certificate ocspSignerBc;
            BCAX.X509Name responderName = basicOcspResp.ResponderId.ToAsn1Object().Name;
            byte[] keyHash = basicOcspResp.ResponderId.ToAsn1Object().GetKeyHash();
            if (responderName != null)
            {
                //Get the signer certificate via name
                var selector = new BCS.X509CertStoreSelector();
                selector.Subject = responderName;
                ocspSignerBc = basicOcspResp
                    .GetCertificates("Collection")
                    .GetMatches(selector)
                    .Cast<BCX.X509Certificate>()
                    .FirstOrDefault();
            } 
            else if (keyHash != null) 
            {
                //Get the signer certificate via key hash
                var sha1 = SHA1.Create();
                ocspSignerBc = basicOcspResp
                    .GetCertificates("Collection")
                    .GetMatches(null)
                    .Cast<BCX.X509Certificate>()
                    .Where(c => {
                        byte[] certKey = c.CertificateStructure.SubjectPublicKeyInfo.PublicKeyData.GetBytes();
                        byte[] certkeyHash = sha1.ComputeHash(certKey);
                        return Enumerable.SequenceEqual(certkeyHash, keyHash);
                    })
                    .FirstOrDefault();
            } 
            else
            { 
                trace.TraceEvent(TraceEventType.Error, 0, "OCSP response for {0} does not have a ResponderID", certificate.Subject);
                throw new RevocationUnknownException("OCSP response for {0} does not have a ResponderID");
            }

            if (ocspSignerBc == null)
                throw new RevocationUnknownException("The OCSP is signed by a unknown certificate");

            //verify the response signature
            if (!basicOcspResp.Verify(ocspSignerBc.GetPublicKey()))
                throw new RevocationUnknownException("The OCSP has an invalid signature");


            //OCSP must be issued by same issuer an the certificate that it validates.
            try
            {
                if (!ocspSignerBc.IssuerDN.Equals(issuerBC.SubjectDN)) throw new ApplicationException();
                ocspSignerBc.Verify(issuerBC.GetPublicKey());
            }
            catch (Exception e)
            {
                throw new RevocationUnknownException("The OCSP signer was not issued by the proper CA", e);
            }

            //verify if the OCSP signer certificate is stil valid
            if (!ocspSignerBc.IsValid(basicOcspResp.ProducedAt))
                throw new RevocationUnknownException("The OCSP signer was not valid at the time the ocsp was issued");


            //check if the signer may issue OCSP
            IList ocspSignerExtKeyUsage = ocspSignerBc.GetExtendedKeyUsage();
            if (!ocspSignerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.9"))
                throw new RevocationUnknownException("The OCSP is signed by a certificate that isn't allowed to sign OCSP");

            //finally, check if the certificate is revoked or not
            var revokedStatus = (BCO.RevokedStatus)singleOcspResp.GetCertStatus();
            if (revokedStatus != null)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "OCSP response for {0} indicates that the certificate is revoked on {1}", certificate.Subject, revokedStatus.RevocationTime);
                if (maxTime >= revokedStatus.RevocationTime)
                    throw new RevocationException<BCAO.BasicOcspResponse>(basicOcspResponse, "The certificate was revoked on " + revokedStatus.RevocationTime.ToString("o"));
            }

            return basicOcspResponse;
        }

        /// <summary>
        /// Validates the cert with the provided crl responses.
        /// </summary>
        /// <param name="certificate">The cert to validate</param>
        /// <param name="issuer">The issuer of the cert to validate</param>
        /// <param name="validationTime">The time on which the cert was needed to validated</param>
        /// <param name="certLists">The list of crls  to use</param>
        /// <returns>The crl response that was used, <c>null</c> if none used</returns>
        /// <exception cref="RevocationException{T}">When the certificate was revoked on the provided time</exception>
        /// <exception cref="RevocationUnknownException">When the certificate (or the crl) can't be validated</exception>
        public static BCAX.CertificateList Verify(this X509Certificate2 certificate, X509Certificate2 issuer, DateTime validationTime, IList<BCAX.CertificateList> certLists)
        {
            DateTime minTime = validationTime - ClockSkewness;
            DateTime maxTime = validationTime + ClockSkewness;
            BCX.X509Certificate certificateBC = DotNetUtilities.FromX509Certificate(certificate);
            BCX.X509Certificate issuerBC = DotNetUtilities.FromX509Certificate(issuer);

            ValueWithRef<BCX.X509Crl, BCAX.CertificateList> crlWithOrg = certLists
                .Select((c) => new ValueWithRef<BCX.X509Crl, BCAX.CertificateList>(new BCX.X509Crl(c), c)) //convert, keep orginal
                .Where((c) => c.Value.IssuerDN.Equals(certificateBC.IssuerDN))
                .Where((c) => c.Value.ThisUpdate >= minTime || (c.Value.NextUpdate != null && c.Value.NextUpdate.Value >= minTime))
                .OrderByDescending((c) => c.Value.ThisUpdate)
                .FirstOrDefault();

            if (crlWithOrg == null)
                return null;

            BCX.X509Crl crl = crlWithOrg.Value;
            BCAX.CertificateList certList = crlWithOrg.Reference;

            //check the signature (no need the check the issuer here)
            try
            {
                crl.Verify(issuerBC.GetPublicKey());
            }
            catch (Exception e)
            {
                throw new RevocationUnknownException("The CRL has an invalid signature", e);
            }

            //check the signer (only the part relevant for CRL)
            if (!issuerBC.GetKeyUsage()[6])
            {
                throw new RevocationUnknownException("The CRL was signed with a certificate that isn't allowed to sign CRLs");
            }

            //check if the certificate is revoked
            BCX.X509CrlEntry crlEntry = crl.GetRevokedCertificate(certificateBC.SerialNumber);
            if (crlEntry != null)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "CRL indicates that {0} is revoked on {1}", certificate.Subject, crlEntry.RevocationDate);
                if (maxTime >= crlEntry.RevocationDate)
                {
                    throw new RevocationException<BCAX.CertificateList>(certList, "The certificate was revoked on " + crlEntry.RevocationDate.ToString("o"));
                }
            }

            return certList;
        }


        /// <summary>
        /// Gets the OCSP response from the server.
        /// </summary>
        /// <remarks>
        /// Never returns an exception.
        /// </remarks>
        /// <param name="cert">The certificate to get the server info from</param>
        /// <param name="issuer">The issue certificate of the certificate to get the server info from</param>
        /// <returns>The OCSP response (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static BCAO.OcspResponse GetOcspResponse(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            Exception lastException = null;
            foreach (Uri uri in cert.GetOCSPUris())
            {
                try
                {
                    BCO.OcspReq ocspReq = cert.GetOcspReqBody(issuer);
                    byte[] ocspReqBytes = ocspReq.GetEncoded();

                    Stream ocspWebReqStream;
                    var webReq = GetOcspWebRequest(uri, ocspReqBytes, out ocspWebReqStream);

                    ocspWebReqStream.Write(ocspReqBytes, 0, ocspReqBytes.Length);

                    var webRsp = (HttpWebResponse)webReq.GetResponse();
                    Stream webRspStream = webRsp.GetResponseStream();
                    using (webRsp)
                    {
                        VerifyOCSPRsp(webRsp);

                        MemoryStream rspStream = new MemoryStream();
                        webRspStream.CopyTo(rspStream);

                        return ParseOCSPResponse(rspStream.ToArray());
                    }
                }
                catch (Exception e)
                {
                    lastException = e;
                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain ocsp: {0}", e);
                }
            }
            if (lastException != null) throw lastException;
            return null;
        }

        /// <summary>
        /// Gets the OCSP response from the server.
        /// </summary>
        /// <remarks>
        /// Never returns an exception.
        /// </remarks>
        /// <param name="cert">The certificate to get the server info from</param>
        /// <param name="issuer">The issue certificate of the certificate to get the server info from</param>
        /// <returns>The OCSP response (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static async Task<BCAO.OcspResponse> GetOcspResponseAsync(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            Exception lastException = null;
            foreach (Uri uri in cert.GetOCSPUris())
            {
                try
                {
                    BCO.OcspReq ocspReq = cert.GetOcspReqBody(issuer);
                    byte[] ocspReqBytes = ocspReq.GetEncoded();

                    Stream ocspWebReqStream;
                    var webReq = GetOcspWebRequest(uri, ocspReqBytes, out ocspWebReqStream);

                    await ocspWebReqStream.WriteAsync(ocspReqBytes, 0, ocspReqBytes.Length);

                    var webRsp = (HttpWebResponse)webReq.GetResponse();
                    Stream webRspStream = webRsp.GetResponseStream();
                    using (webRsp)
                    {
                        MemoryStream rspStream = new MemoryStream();
                        Task cpy = webRspStream.CopyToAsync(rspStream);

                        VerifyOCSPRsp(webRsp);

                        await cpy;

                        return ParseOCSPResponse(rspStream.ToArray());
                    }
                }
                catch (Exception e)
                {
                    lastException = e;
                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain ocsp: {0}", e);
                }
            }
            if (lastException != null) throw lastException;
            return null;
        }

        private static HttpWebRequest GetOcspWebRequest(Uri uri, byte[] body, out Stream stream)
        {
            var webReq = (HttpWebRequest)WebRequest.Create(uri);
            webReq.Method = "POST";
            webReq.ContentType = "application/ocsp-request";
            webReq.ContentLength = body.Length;
            stream = webReq.GetRequestStream();
            return webReq;
        }

        private static BCO.OcspReq GetOcspReqBody(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            var ocspReqGen = new BCO.OcspReqGenerator();
            ocspReqGen.AddRequest(
                new BCO.CertificateID(BCO.CertificateID.HashSha1,
                    DotNetUtilities.FromX509Certificate(issuer),
                    DotNetUtilities.FromX509Certificate(cert).SerialNumber));
            return ocspReqGen.Generate();
        }

        private static BCAO.OcspResponse ParseOCSPResponse(byte[] ocspRspBytes)
        {
            BCAO.OcspResponse ocspResponse = BCAO.OcspResponse.GetInstance(BCA.Asn1Sequence.FromByteArray(ocspRspBytes));
            if (ocspResponse.ResponseStatus.IntValueExact != BCAO.OcspResponseStatus.Successful)
            {
                throw new RevocationUnknownException("OCSP Response with invalid status: " + ocspResponse.ResponseStatus.IntValueExact);
            }
            return ocspResponse;
        }

        private static IQueryable<Uri> GetOCSPUris(this X509Certificate2 cert)
        {
            X509Extension crlExtention = cert.Extensions[BCAX.X509Extensions.AuthorityInfoAccess.Id];
            if (crlExtention == null)
                return Enumerable.Empty<Uri>().AsQueryable();

            var aia = BCAX.AuthorityInformationAccess.GetInstance(BCA.Asn1Sequence.FromByteArray(crlExtention.RawData));
            return aia.GetAccessDescriptions().AsQueryable()
                .Where((ad) => ad.AccessMethod.Id == BCAX.AccessDescription.IdADOcsp.Id)
                .Select((ad) => ad.AccessLocation)
                .Where((gn) => gn.TagNo == BCAX.GeneralName.UniformResourceIdentifier && gn.Name is BCA.DerStringBase)
                .Select((gn) => new Uri(((BCA.DerStringBase)gn.Name).GetString()))
                .Where((u) => u.Scheme == "http" || u.Scheme == "https");
        }

        private static void VerifyOCSPRsp(HttpWebResponse webRsp)
        {
            if (webRsp.StatusCode != HttpStatusCode.OK
                || webRsp.ContentType != "application/ocsp-response")
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status or contentype for ocsp response: " + webRsp.StatusDescription);
                throw new RevocationUnknownException("Response with invalid status or contenttype for ocsp response: " + webRsp.StatusDescription);
            }
        }

        /// <summary>
        /// Download the crl from the server
        /// </summary>
        /// <param name="cert">the certificat to get the server info from</param>
        /// <returns>The clr (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static BCAX.CertificateList GetCertificateList(this X509Certificate2 cert)
        {
            Exception lastException = null;
            foreach (Uri uri in cert.GetCrlWebUris())
            {
                try
                {
                    var webReq = (HttpWebRequest)WebRequest.Create(uri);
                    using (var webRsp = (HttpWebResponse)webReq.GetResponse())
                    {
                        Stream webRspStream = webRsp.GetResponseStream();
                        VerifyCrlRsp(webRsp);

                        MemoryStream rspStream = new MemoryStream();
                        webRspStream.CopyTo(rspStream);

                        return BCAX.CertificateList.GetInstance(BCA.Asn1Sequence.FromByteArray(rspStream.ToArray()));
                    }
                }
                catch (Exception e)
                {
                    lastException = e;
                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain crl: {0}", e);
                }
            }
            if (lastException != null) throw lastException;
            return null;
        }

        /// <summary>
        /// Download the crl from the server
        /// </summary>
        /// <param name="cert">the certificat to tge the server info from</param>
        /// <returns>The clr (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static async Task<BCAX.CertificateList> GetCertificateListAsync(this X509Certificate2 cert)
        {
            Exception lastException = null;
            foreach (Uri uri in cert.GetCrlWebUris())
            {
                try
                {
                    var webReq = (HttpWebRequest)WebRequest.Create(uri);
                    using (var webRsp = (HttpWebResponse)webReq.GetResponse())
                    {
                        Stream webRspStream = webRsp.GetResponseStream();

                        MemoryStream rspStream = new MemoryStream();
                        Task rspCopy = webRspStream.CopyToAsync(rspStream);

                        VerifyCrlRsp(webRsp);

                        await rspCopy;

                        return BCAX.CertificateList.GetInstance(BCA.Asn1Sequence.FromByteArray(rspStream.ToArray()));
                    }
                }
                catch (Exception e)
                {
                    lastException = e;
                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain crl: {0}", e);
                }
            }
            if (lastException != null) throw lastException;
            return null;
        }

        private static void VerifyCrlRsp(HttpWebResponse webRsp)
        {
            if (webRsp.StatusCode != HttpStatusCode.OK)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status for crl reply: " + webRsp.StatusDescription);
                throw new RevocationUnknownException("Response with invalid status the crl reply: " + webRsp.StatusDescription);
            }
        }

        private static IQueryable<Uri> GetCrlWebUris(this X509Certificate2 cert)
        {
            X509Extension crlExtention = cert.Extensions[BCAX.X509Extensions.CrlDistributionPoints.Id];
            if (crlExtention == null)
                return Enumerable.Empty<Uri>().AsQueryable(); ;

            var distributionPoint = BCAX.CrlDistPoint.GetInstance(BCA.Asn1Sequence.FromByteArray(crlExtention.RawData));
            return distributionPoint.GetDistributionPoints().AsQueryable()
                .Select((dp) => dp.DistributionPointName.Name)
                .Cast<BCAX.GeneralNames>()
                .SelectMany((gns) => gns.GetNames())
                .Where((gn) => gn.TagNo == BCAX.GeneralName.UniformResourceIdentifier && gn.Name is BCA.DerStringBase)
                .Select((gn) => new Uri(((BCA.DerStringBase)gn.Name).GetString()))
                .Where((u) => u.Scheme == "http" || u.Scheme == "https");
        }


        internal static void AddErrorStatus(List<X509ChainStatus> chainStatus, List<X509ChainStatus> elementStatus, X509ChainStatusFlags extraStatusFlag, String extraStatusInfo)
        {
            X509ChainStatus extraStatus = new X509ChainStatus();
            extraStatus.Status = extraStatusFlag;
            extraStatus.StatusInformation = extraStatusInfo;
            if (chainStatus != null) AddErrorStatus(chainStatus, extraStatus);
            if (elementStatus != null) AddErrorStatus(elementStatus, extraStatus);
        }

        private static void AddErrorStatus(List<X509ChainStatus> status, X509ChainStatus extraStatus)
        {
            foreach (X509ChainStatus noErrorStatus in status.Where(x => x.Status == X509ChainStatusFlags.NoError))
            {
                status.Remove(noErrorStatus);
            }
            if (status.Count(x => x.Status == extraStatus.Status) == 0) status.Add(extraStatus);
        }
    }
}
