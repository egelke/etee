/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014-2015 Egelke BVBA
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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Egelke.EHealth.Client.Pki
{
    public static class X509CertificateHelper
    {
        private const int CRYPT_E_EXISTS = unchecked((int)0x80092005);

        private static readonly TimeSpan ClockSkewness = new TimeSpan(0, 1, 0);
        private static readonly TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");
        
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps)
        {
            return cert.BuildChain(validationTime, extraStore, ref crls, ref ocsps, false, new TimeSpan(1, 0, 0));
        }

        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps, bool checkHistoricalSuspend, TimeSpan maxDelay)
        {
            if (validationTime.Kind != DateTimeKind.Utc)
                throw new ArgumentException("The time must be UTC", "validationTime");

            DateTime now = DateTime.UtcNow;
            if (validationTime > (now + ClockSkewness))
            {
                throw new ArgumentException("validation can't occur in the future", "validationTime");
            }

            //Add off-line revocation info to the store
            var intCas = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            intCas.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            try
            {
                foreach (CertificateList crl in crls)
                {
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Adding CRL to store: {0} of {1}", crl.Issuer, crl.ThisUpdate.ToDateTime());
                    byte[] crlBytes = crl.GetDerEncoded();
                    if (!CertAddEncodedCRLToStore(intCas.StoreHandle, CertEncodingType.PKCS_7_ASN | CertEncodingType.X509_ASN, crlBytes, crlBytes.Length, CertStoreAddDisposition.NEWER, IntPtr.Zero))
                    {
                        int error = Marshal.GetHRForLastWin32Error();
                        if (error != CRYPT_E_EXISTS)
                            trace.TraceEvent(TraceEventType.Warning, 0, "Failed to add off-line CRL from {1} of {0} to store", crl.NextUpdate.GetTime(), crl.Issuer.ToString());
                        else
                            trace.TraceEvent(TraceEventType.Verbose, 0, "off-line CRL from {1} of {0} already in store", crl.NextUpdate.GetTime(), crl.Issuer.ToString());
                    }
                    else
                        trace.TraceEvent(TraceEventType.Verbose, 0, "off-line CRL from {1} of {0} added to store", crl.NextUpdate.GetTime(), crl.Issuer.ToString());
                }
            }
            finally
            {
                intCas.Close();
            }

            //create the X509 chain
            X509Chain x509Chain = new X509Chain();
            if (extraStore != null) x509Chain.ChainPolicy.ExtraStore.AddRange(extraStore);
            x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            x509Chain.ChainPolicy.VerificationTime = validationTime;
        winRevocationCheck:
            x509Chain.Build(cert);

            //create the chain using the information from the X509 Chain
            Chain chain = new Chain();
            foreach (var status in x509Chain.ChainStatus)
            {
                trace.TraceEvent(status.Status != X509ChainStatusFlags.NoError ? TraceEventType.Warning : TraceEventType.Information, 0,
                    "The certificate chain for {0} has a status {1}: {2}", cert.Subject, status.Status, status.StatusInformation);
                if (status.Status != X509ChainStatusFlags.RevocationStatusUnknown
                    && status.Status != X509ChainStatusFlags.Revoked
                    && status.Status != X509ChainStatusFlags.OfflineRevocation)
                {
                    chain.ChainStatus.Add(status);
                }
            }

            //marshal the chain context to extract the CRL/OCSP
            CERT_SIMPLE_CHAIN? csc = null;
            var ccc = (CERT_CHAIN_CONTEXT)Marshal.PtrToStructure(x509Chain.ChainContext, typeof(CERT_CHAIN_CONTEXT));
            if (ccc.rgpChain != IntPtr.Zero)
            {
                //read the first (and only) element of the array
                var cscPtr = Marshal.ReadIntPtr(ccc.rgpChain);
                if (cscPtr != IntPtr.Zero)
                {
                    //marshal the simple chain
                    csc = (CERT_SIMPLE_CHAIN)Marshal.PtrToStructure(cscPtr, typeof(CERT_SIMPLE_CHAIN));
                }
            }


            //create the certificate chain 
            int index = 0;
            X509ChainElementEnumerator x509Elements = x509Chain.ChainElements.GetEnumerator();
            if (x509Elements.MoveNext())
            {
                ChainElement currentElement = new ChainElement(x509Elements.Current);
                chain.ChainElements.Add(currentElement);
                while (x509Elements.MoveNext())
                {
                    ChainElement issuerElement = new ChainElement(x509Elements.Current);

                    //calculate a new check based on the input
                    X509CertificateStatus statusCheck = new X509CertificateStatus(currentElement.Certificate, issuerElement.Certificate);

                    //set basic info
                    statusCheck.ValidationTime = validationTime;
                    statusCheck.OcspOnly = index == 0;
                    statusCheck.CheckSuspend = index == 0 && checkHistoricalSuspend;
                    statusCheck.MaxDelay = maxDelay;
                    statusCheck.ClockSkewness = ClockSkewness;
                    trace.TraceEvent(TraceEventType.Verbose, 0, "Checking revocation of {0} on {1} ", currentElement.Certificate.Subject, validationTime);

                    //set the  latest OCSP or CRL, obtained from the native context
                    if (csc != null)
                    {
                        var csePtr = Marshal.ReadIntPtr(new IntPtr((long)csc.Value.rgpElement + (index * IntPtr.Size)));
                        var cse = (CERT_CHAIN_ELEMENT)Marshal.PtrToStructure(csePtr, typeof(CERT_CHAIN_ELEMENT));
                        if (cse.pRevocationInfo != IntPtr.Zero)
                        {
                            var cri = (CERT_REVOCATION_INFO)Marshal.PtrToStructure(cse.pRevocationInfo, typeof(CERT_REVOCATION_INFO));
                            if (cri.pCrlInfo != IntPtr.Zero)
                            {
                                var crci = (CERT_REVOCATION_CRL_INFO)Marshal.PtrToStructure(cri.pCrlInfo, typeof(CERT_REVOCATION_CRL_INFO));
                                if (crci.pBaseCRLContext != IntPtr.Zero)
                                {
                                    var cc = (CRL_CONTEXT)Marshal.PtrToStructure(crci.pBaseCRLContext, typeof(CRL_CONTEXT));

                                    byte[] crlBytes = new byte[cc.cbCrlEncoded];
                                    Marshal.Copy(cc.pbCrlEncoded, crlBytes, 0, cc.cbCrlEncoded);
                                    CertificateList crl = CertificateList.GetInstance(Asn1Sequence.FromByteArray(crlBytes));

                                    bool isOcspWrapper = false;
                                    TbsCertificateList tbsCrl = crl.TbsCertList;
                                    if (tbsCrl.Extensions != null)
                                    {
                                        Org.BouncyCastle.Asn1.X509.X509Extension crlExt = tbsCrl.Extensions.GetExtension(OcspObjectIdentifiers.PkixOcspBasic);
                                        if (crlExt != null)
                                        {
                                            isOcspWrapper = true;
                                            Asn1Encodable ocspAsn1 = crlExt.GetParsedValue();
                                            OcspResponse ocsp = OcspResponse.GetInstance(ocspAsn1);
                                            statusCheck.NewOcspResponse = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(ocsp.ResponseBytes.Response.GetOctets()));
                                            trace.TraceEvent(TraceEventType.Verbose, 0, "Found new OCSP response of {0} from {1} ", currentElement.Certificate.Subject, statusCheck.NewOcspResponse.TbsResponseData.ProducedAt.ToDateTime());
                                        }
                                    }
                                    if (!isOcspWrapper)
                                    {
                                        statusCheck.NewCertList = crl;
                                        trace.TraceEvent(TraceEventType.Verbose, 0, "Found new CRL response of {0} from {1} ", currentElement.Certificate.Subject, statusCheck.NewCertList.ThisUpdate.ToDateTime());
                                    }
                                }
                            }
                        }
                    }

                    //Add revocation status info that is manually retrieved.
                    X509ChainStatus status = statusCheck.Calculate(ref crls, ref ocsps);
                    if (status.Status == X509ChainStatusFlags.RevocationStatusUnknown
                        && x509Chain.ChainPolicy.RevocationMode != X509RevocationMode.Online)
                    {
                        //revocation status unknown, start over on-line
                        trace.TraceEvent(TraceEventType.Information, 0, "Revocation status unknown, trying again on-line");

                        chain.ChainElements.Clear();

                        x509Chain.Reset();
                        x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;

                        goto winRevocationCheck;
                    }
                    else
                    {
                        trace.TraceEvent(status.Status != X509ChainStatusFlags.NoError ? TraceEventType.Warning : TraceEventType.Information, 0,
                            "The certificate {0} has a status {1}: {2}", currentElement.Certificate.Subject, status.Status, status.StatusInformation);
                        if (status.Status != X509ChainStatusFlags.NoError)
                        {
                            AddErrorStatus(chain.ChainStatus, status);
                            AddErrorStatus(currentElement.ChainElementStatus, status);
                        }
                        chain.ChainElements.Add(currentElement);
                    }                    

                    //Move to next
                    index++;
                    currentElement = issuerElement;
                }

                //add the root element (no revocation info)
                chain.ChainElements.Add(currentElement); 
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

        [DllImport("CRYPT32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal extern static bool CertAddEncodedCRLToStore(
                [In]            IntPtr hCertStore,
                [In]            CertEncodingType dwCertEncodingType,
                [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] pbCrlEncoded,
                [In]            int cbCrlEncoded,
                [In]            CertStoreAddDisposition dwAddDisposition,
                [Out]           IntPtr ppCrlContext
            );
    }

    [Flags]
    internal enum CertEncodingType : uint
    {
        CRYPT_ASN = 0x00000001,
        CRYPT_NDR = 0x00000002,
        X509_ASN = 0x00000001,
        X509_NDR = 0x00000002,
        PKCS_7_ASN = 0x00010000,
        PKCS_7_NDR = 0x00020000
    }

    internal enum CertStoreAddDisposition : uint
    {
        NEW = 1,
        EXISTING = 2,
        REPLACE_EXISTING = 3,
        ALWAYS = 4,
        REPLACE_EXISTING_INHERIT_PROPERTIES = 5,
        NEWER = 6,
        NEWER_INHERIT_PROPERTIES = 7
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CERT_CHAIN_CONTEXT
    {
        internal uint cbSize;
        internal uint dwErrorStatus;   // serialized CERT_TRUST_STATUS
        internal uint dwInfoStatus;    // serialized CERT_TRUST_STATUS
        internal uint cChain;
        internal IntPtr rgpChain;                    // PCERT_SIMPLE_CHAIN*
        internal uint cLowerQualityChainContext;
        internal IntPtr rgpLowerQualityChainContext; // PCCERT_CHAIN_CONTEXT*
        internal uint fHasRevocationFreshnessTime; // Note that we declare the field as a uint here since we are manipulating 
                                                   // the structure manually and a bool is only 1 byte in the managed world.
        internal uint dwRevocationFreshnessTime;   // seconds
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CERT_SIMPLE_CHAIN
    {
        internal uint cbSize;
        internal uint dwErrorStatus;   // serialized CERT_TRUST_STATUS
        internal uint dwInfoStatus;    // serialized CERT_TRUST_STATUS
        internal uint cElement;
        internal IntPtr rgpElement;      // PCERT_CHAIN_ELEMENT*
        internal IntPtr pTrustListInfo;
        internal uint fHasRevocationFreshnessTime; // Note that we declare the field as a uint here since we are manipulating 
                                                   // the structure manually and a bool is only 1 byte in the managed world.
        internal uint dwRevocationFreshnessTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CERT_CHAIN_ELEMENT
    {
        internal uint cbSize;
        internal IntPtr pCertContext;
        internal uint dwErrorStatus;   // serialized CERT_TRUST_STATUS
        internal uint dwInfoStatus;    // serialized CERT_TRUST_STATUS
        internal IntPtr pRevocationInfo;
        internal IntPtr pIssuanceUsage;
        internal IntPtr pApplicationUsage;
        internal IntPtr pwszExtendedErrorInfo;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CERT_REVOCATION_INFO
    {
        internal uint cbSize;
        internal uint dwRevocationResult;
        [MarshalAs(UnmanagedType.LPStr)]
        internal String pszRevocationOid;
        internal IntPtr pvOidSpecificInfo;
        internal uint fHasFreshnessTime;
        internal uint dwFreshnessTime;
        internal IntPtr pCrlInfo;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CERT_REVOCATION_CRL_INFO
    {
        internal uint cbSize;
        internal IntPtr pBaseCRLContext;
        internal IntPtr pDeltaCRLContext;
        internal IntPtr pCrlEntry;
        internal uint fDeltaCrlEntry;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CRL_CONTEXT
    {
        internal CertEncodingType dwCertEncodingType;
        internal IntPtr pbCrlEncoded;
        internal int cbCrlEncoded;
        internal IntPtr pCrlInfo;
        internal IntPtr hCertStore;
    }
}
