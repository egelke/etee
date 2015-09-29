using System;
using System.Linq;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509.Store;
using BCx = Org.BouncyCastle.X509;
using BCax = Org.BouncyCastle.Asn1.X509;
using BCuc = Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Security;
using System.Collections;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Egelke.EHealth.Client.Pki.Test
{
    public class MyPkixCertPathChecker : PkixCertPathChecker
    {
        public override void Check(BCx.X509Certificate cert, ICollection unresolvedCritExts)
        {
            throw new NotImplementedException();
        }

        public override BCuc.ISet GetSupportedExtensions()
        {
            throw new NotImplementedException();
        }

        public override void Init(bool forward)
        {

        }

        public override bool IsForwardCheckingSupported()
        {
            throw new NotImplementedException();
        }
    }

    [TestFixture]
    public class PKIXCertPathBuilderTest
    {
        private const int CRYPT_E_EXISTS = unchecked((int)0x80092005);

        X509Store rootCas;
        X509Store intCas;
        X509Certificate2 endCert;
        X509Certificate2 intCaCert;


        [SetUp]
        public void Setup()
        {
            endCert = new X509Certificate2("files/eid79021802145.crt");
            intCaCert = new X509Certificate2("files/Citizen201204.crt");
            rootCas = new X509Store(StoreName.AuthRoot, StoreLocation.CurrentUser);
            rootCas.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

            intCas = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            intCas.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
        }

        [Test]
        public void BuildChain()
        {
            var selector = new X509CertStoreSelector();
            selector.Certificate = DotNetUtilities.FromX509Certificate(endCert);

            var trustAnchors = new BCuc::HashSet();
            foreach (X509Certificate2 cert in rootCas.Certificates)
            {
                trustAnchors.Add(new TrustAnchor(DotNetUtilities.FromX509Certificate(cert), null));
            }

            var pkixParams = new PkixBuilderParameters(trustAnchors, selector);
            pkixParams.IsRevocationEnabled = false;
            pkixParams.AddCertPathChecker(new MyPkixCertPathChecker());


            var additionalCerts = new ArrayList();
            additionalCerts.Add(selector.Certificate);
            foreach (X509Certificate2 cert in intCas.Certificates)
            {
                additionalCerts.Add(DotNetUtilities.FromX509Certificate(cert));
            }
            var additionalCertStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", new X509CollectionStoreParameters(additionalCerts));
            pkixParams.AddStore(additionalCertStore);

            var builder = new PkixCertPathBuilder();
            PkixCertPathBuilderResult result = builder.Build(pkixParams);

        }

        [Test]
        public void AdvancedChainBuild()
        {
            X509Chain x509Chain = new X509Chain();
            x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            x509Chain.ChainPolicy.ExtraStore.Add(intCaCert);
            
            byte[] c201404crl = File.ReadAllBytes("files/Citizen201204-2.crl");
            if (!CertAddEncodedCRLToStore(intCas.StoreHandle, CertEncodingType.PKCS_7_ASN | CertEncodingType.X509_ASN, c201404crl, c201404crl.Length, CertStoreAddDisposition.NEWER, IntPtr.Zero))
            {
                int error = Marshal.GetLastWin32Error();
                
                if (error != CRYPT_E_EXISTS)
                    Assert.Fail(String.Format("Failed to add CRL: {0:x}", error));
            }
            x509Chain.Build(endCert);

            CERT_CHAIN_CONTEXT ccc = (CERT_CHAIN_CONTEXT) Marshal.PtrToStructure(x509Chain.ChainContext, typeof(CERT_CHAIN_CONTEXT));
            IntPtr cscPtr = Marshal.ReadIntPtr(ccc.rgpChain);

            //There is only 1 so we read only one
            //TODO: protect against short structure (http://referencesource.microsoft.com/#System/security/system/security/cryptography/x509/x509chainelement.cs,8dcf8d1dc3978ed0)
            CERT_SIMPLE_CHAIN csc = (CERT_SIMPLE_CHAIN) Marshal.PtrToStructure(cscPtr, typeof(CERT_SIMPLE_CHAIN));

            for (int i=0; i<csc.cElement; i++)
            {
                IntPtr csePtr = Marshal.ReadIntPtr(new IntPtr((long)csc.rgpElement + i * IntPtr.Size));
                CERT_CHAIN_ELEMENT cse = (CERT_CHAIN_ELEMENT)Marshal.PtrToStructure(csePtr, typeof(CERT_CHAIN_ELEMENT));
                if (cse.pRevocationInfo != IntPtr.Zero)
                {
                    CERT_REVOCATION_INFO cri = (CERT_REVOCATION_INFO)Marshal.PtrToStructure(cse.pRevocationInfo, typeof(CERT_REVOCATION_INFO));
                    CERT_REVOCATION_CRL_INFO crci = (CERT_REVOCATION_CRL_INFO)Marshal.PtrToStructure(cri.pCrlInfo, typeof(CERT_REVOCATION_CRL_INFO));
                    CRL_CONTEXT cc = (CRL_CONTEXT)Marshal.PtrToStructure(crci.pBaseCRLContext, typeof(CRL_CONTEXT));

                    byte[] crlBytes = new byte[cc.cbCrlEncoded];
                    Marshal.Copy(cc.pbCrlEncoded, crlBytes, 0, cc.cbCrlEncoded);
                    CertificateList crl = CertificateList.GetInstance(Asn1Sequence.FromByteArray(crlBytes));

                    TbsCertificateList tbsCrl = crl.TbsCertList;
                    if (tbsCrl.Extensions != null) {
                        BCax::X509Extension crlExt = tbsCrl.Extensions.GetExtension(OcspObjectIdentifiers.PkixOcspBasic);
                        Asn1Encodable ocspAsn1 = crlExt.GetParsedValue();
                        OcspResponse ocsp = OcspResponse.GetInstance(ocspAsn1);
                        BasicOcspResponse basicOcsp = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(ocsp.ResponseBytes.Response.GetOctets()));
                    }
                }
            }

            Assert.AreEqual(0, x509Chain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.RevocationStatusUnknown),
                "Revocation issue");
            Assert.AreEqual(0, x509Chain.ChainStatus.Count(x => x.Status != X509ChainStatusFlags.NoError),
                "Other error");
        }

        [DllImport("CRYPT32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CertAddEncodedCRLToStore(
            [In] IntPtr hCertStore,
            [In] CertEncodingType dwCertEncodingType,
            [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3)] byte[] pbCrlEncoded,
            [In] int cbCrlEncoded,
            [In] CertStoreAddDisposition dwAddDisposition,
            [Out] IntPtr ppStoreContext);


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


    [Flags]
    public enum CertEncodingType : uint
    {
        CRYPT_ASN = 0x00000001,
        CRYPT_NDR = 0x00000002,
        X509_ASN = 0x00000001,
        X509_NDR = 0x00000002,
        PKCS_7_ASN = 0x00010000,
        PKCS_7_NDR = 0x00020000
    }

    public enum CertStoreAddDisposition : uint
    {
        NEW = 1,
        EXISTING = 2,
        REPLACE_EXISTING = 3,
        ALWAYS = 4,
        REPLACE_EXISTING_INHERIT_PROPERTIES = 5,
        NEWER = 6,
        NEWER_INHERIT_PROPERTIES = 7
    }

}
