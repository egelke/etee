using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace Egelke.EHealth.Client.Pki.Test
{
    public static class TestHelper
    {
        public static TimeSpan INTERVAL = TimeSpan.FromMinutes(2);

        public static DateTime Floor(this DateTime dateTime)
        {
            return dateTime.AddTicks(-(dateTime.Ticks % INTERVAL.Ticks));
        }
    }

    [TestClass]
    public class X509CertificateHelperTest
    {
        public static X509Certificate2 newEid;
        public static X509Certificate2 newEidIssuer;
        public static BasicOcspResponse newEidOcsp;

        public static X509Certificate2 oldEid;
        public static X509Certificate2 oldEidIssuer;
        public static BasicOcspResponse oldEidOcsp;
        public static BasicOcspResponse oldEidOcsp2;
        public static CertificateList oldEidCrl;

        [ClassInitialize]
        public static void InitClass(TestContext ctx)
        {
            newEid = new X509Certificate2(@"files/eid79021802145-2027.crt");
            newEidIssuer = new X509Certificate2(@"files/Citizen201709.crt");
            OcspResponse ocspMsg = OcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/eid79021802145-2027.ocsp-rsp")));
            newEidOcsp = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(ocspMsg.ResponseBytes.Response.GetOctets()));

            oldEid = new X509Certificate2(@"files/eid79021802145.crt");
            oldEidIssuer = new X509Certificate2(@"files/Citizen201204.crt");
            oldEidOcsp = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/eid79021802145.ocsp")));
            oldEidOcsp2 = BasicOcspResponse.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/eid79021802145-2.ocsp")));
            oldEidCrl = CertificateList.GetInstance(Asn1Sequence.GetInstance(File.ReadAllBytes(@"files/eid79021802145.crl")));
        }


        [TestMethod]
        public void OcspNoCheckOcspRsp_True()
        {
            var target = new X509Certificate2(@"files/ocspRsp.crt");

            bool result = target.IsOcspNoCheck();

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void OcspNoCheckNewEid_False()
        {
            var target = newEid;

            bool result = target.IsOcspNoCheck();

            Assert.IsFalse(result);
        }

        [TestMethod]
        public void VerifyOCSPOfOldEid_NotFound()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;
            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(oldEidOcsp);
            revocationInfo.Add(oldEidOcsp2);

            BasicOcspResponse result = target.Verify(issuer, DateTime.UtcNow, revocationInfo);

            Assert.IsNull(result);
        }

        [TestMethod]
        public void VerifyOCSPOfOldEid_LastOfMultiple()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;
            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(oldEidOcsp);
            revocationInfo.Add(oldEidOcsp2);

            BasicOcspResponse result = target.Verify(issuer, new DateTime(2014, 3, 4, 0, 0, 0, DateTimeKind.Utc), revocationInfo);

            Assert.IsNotNull(result);
            Assert.AreEqual(new DateTime(2014, 3, 5, 20, 41, 18, DateTimeKind.Utc), result.TbsResponseData.ProducedAt.ToDateTime());
        }

        [TestMethod]
        public void VerifyOCSPOfOldEid_Single()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;
            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(oldEidOcsp);

            BasicOcspResponse result = target.Verify(issuer, new DateTime(2014, 3, 4, 0, 0, 0, DateTimeKind.Utc), revocationInfo);

            Assert.IsNotNull(result);
            Assert.AreEqual(new DateTime(2014, 3, 5, 18, 12, 19, DateTimeKind.Utc), result.TbsResponseData.ProducedAt.ToDateTime());
        }

        [TestMethod]
        public void VerifyOCSPOfNewEid_LiveRetrieval()
        {
            var target = newEid;
            var issuer = newEidIssuer;

            OcspResponse ocspMsg = target.GetOcspResponse(issuer);
            BasicOcspResponse liveOcsp = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(ocspMsg.ResponseBytes.Response.GetOctets()));

            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(liveOcsp);
            revocationInfo.Add(newEidOcsp);

            BasicOcspResponse result = target.Verify(issuer, DateTime.UtcNow, revocationInfo);

            Assert.IsNotNull(result);
            Assert.AreEqual(DateTime.UtcNow.Floor(), result.TbsResponseData.ProducedAt.ToDateTime().Floor());
        }

        [TestMethod]
        public void VerifyCrlOfOldEid_NotFound()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            var revocationInfo = new List<CertificateList>();
            revocationInfo.Add(oldEidCrl);

            CertificateList result = target.Verify(issuer, new DateTime(2019, 1, 1, 0, 0, 0, DateTimeKind.Utc), revocationInfo);

            Assert.IsNull(result);
        }

        [TestMethod]
        public void VerifyCrlOfOldEid_Valid()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            var revocationInfo = new List<CertificateList>();
            revocationInfo.Add(oldEidCrl);

            CertificateList result = target.Verify(issuer, new DateTime(2016, 6, 16, 8, 14, 8, DateTimeKind.Utc), revocationInfo);

            Assert.IsNotNull(result);
            Assert.AreEqual(new DateTime(2018, 7, 16, 8, 14, 8, DateTimeKind.Utc), result.ThisUpdate.ToDateTime());
        }

        [TestMethod]
        public void VerifyCrlOfOldEid_Revoked()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            var revocationInfo = new List<CertificateList>();
            revocationInfo.Add(oldEidCrl);

            RevocationException<CertificateList> result = Assert.ThrowsException<RevocationException<CertificateList>>(() =>
                target.Verify(issuer, new DateTime(2017, 5, 30, 23, 59, 59, DateTimeKind.Utc), revocationInfo));

            Assert.AreEqual("The certificate was revoked on 2017-04-27T17:05:15.0000000Z", result.Message);
            Assert.IsNotNull(result.RevocationInfo);
            Assert.AreEqual(new DateTime(2018, 7, 16, 8, 14, 8, DateTimeKind.Utc), result.RevocationInfo.ThisUpdate.ToDateTime());
        }

        [TestMethod]
        public void GetOCSPOfRootCa_NA()
        {
            var target = new X509Certificate2(@"files/belgiumrca4.crt");

            OcspResponse result = target.GetOcspResponse(target);

            Assert.IsNull(result);
        }

        [TestMethod]
        public void GetOCSPOfNewEid_Downloaded()
        {
            var target = newEid;
            var issuer = newEidIssuer;

            OcspResponse result = target.GetOcspResponse(issuer);
            BasicOcspResponse resultDetail = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(result.ResponseBytes.Response.GetOctets()));

            Assert.IsNotNull(result);
            Assert.AreEqual(0, result.ResponseStatus.IntValueExact);
            Assert.IsTrue(resultDetail.TbsResponseData.ProducedAt.ToDateTime() <= DateTime.UtcNow);
        }

        [TestMethod]
        public async Task GetOCSPOfNewEid_DownloadedAsync()
        {
            var target = newEid;
            var issuer = newEidIssuer;

            OcspResponse result = await target.GetOcspResponseAsync(issuer);
            BasicOcspResponse resultDetail = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(result.ResponseBytes.Response.GetOctets()));

            Assert.IsNotNull(result);
            Assert.AreEqual(0, result.ResponseStatus.IntValueExact);
            Assert.IsTrue(resultDetail.TbsResponseData.ProducedAt.ToDateTime() <= DateTime.UtcNow);
        }

        [TestMethod]
        public void GetOCSPOfOldEid_Failed()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            Assert.ThrowsException<RevocationUnknownException>(() => target.GetOcspResponse(target));
        }

        [TestMethod]
        public void GetOCSPOfGoogle_Downloaded()
        {
            var target = new X509Certificate2(@"files/google.crt");
            var issuer = new X509Certificate2(@"files/GTSCA.crt");

            OcspResponse result = target.GetOcspResponse(issuer);
            BasicOcspResponse resultDetail = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(result.ResponseBytes.Response.GetOctets()));

            Assert.IsNotNull(result);
            Assert.AreEqual(0, result.ResponseStatus.IntValueExact);
            Assert.IsTrue(resultDetail.TbsResponseData.ProducedAt.ToDateTime() <= DateTime.UtcNow);
        }

        [TestMethod]
        public void GetCertificateListOfRootCa_NA()
        {
            var target = new X509Certificate2(@"files/belgiumrca4.crt");

            CertificateList result = target.GetCertificateList();

            Assert.IsNull(result);
        }

        [TestMethod]
        public void GetCertificateListOfNewEid_Downloaded()
        {
            var target = newEid;

            CertificateList result = target.GetCertificateList();

            Assert.IsNotNull(result);
            Assert.IsTrue(result.ThisUpdate.ToDateTime() <= DateTime.UtcNow);
            Assert.IsTrue(result.NextUpdate.ToDateTime() >= DateTime.UtcNow);
        }

        [TestMethod]
        public async Task GetCertificateListOfNewEid_DownloadedAsync()
        {
            var target = newEid;

            CertificateList result = await target.GetCertificateListAsync();

            Assert.IsNotNull(result);
            Assert.IsTrue(result.ThisUpdate.ToDateTime() <= DateTime.UtcNow);
            Assert.IsTrue(result.NextUpdate.ToDateTime() >= DateTime.UtcNow);
        }

        [TestMethod]
        public void GetCertificateListWithMulti_DownloadedFirst()
        {
            var target = new X509Certificate2(@"files/linuxize.crt");

            CertificateList result = target.GetCertificateList();

            Assert.IsNotNull(result);
            Assert.IsTrue(result.ThisUpdate.ToDateTime() <= DateTime.UtcNow);
            Assert.IsTrue(result.NextUpdate.ToDateTime() >= DateTime.UtcNow);
        }



    }
}