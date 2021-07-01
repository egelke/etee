using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

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

    public class X509CertificateHelperTest
    {
        public X509Certificate2 newEid;
        public X509Certificate2 newEidIssuer;
        public BasicOcspResponse newEidOcsp;

        public X509Certificate2 oldEid;
        public X509Certificate2 oldEidIssuer;
        public BasicOcspResponse oldEidOcsp;
        public BasicOcspResponse oldEidOcsp2;
        public CertificateList oldEidCrl;

        public X509CertificateHelperTest()
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


        [Fact]
        public void OcspNoCheckOcspRsp_True()
        {
            var target = new X509Certificate2(@"files/ocspRsp.crt");

            bool result = target.IsOcspNoCheck();

            Assert.True(result);
        }

        [Fact]
        public void OcspNoCheckNewEid_False()
        {
            var target = newEid;

            bool result = target.IsOcspNoCheck();

            Assert.False(result);
        }

        [Fact]
        public void VerifyOCSPOfOldEid_NotFound()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;
            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(oldEidOcsp);
            revocationInfo.Add(oldEidOcsp2);

            BasicOcspResponse result = target.Verify(issuer, DateTime.UtcNow, revocationInfo);

            Assert.Null(result);
        }

        [Fact]
        public void VerifyOCSPOfOldEid_LastOfMultiple()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;
            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(oldEidOcsp);
            revocationInfo.Add(oldEidOcsp2);

            BasicOcspResponse result = target.Verify(issuer, new DateTime(2014, 3, 4, 0, 0, 0, DateTimeKind.Utc), revocationInfo);

            Assert.NotNull(result);
            Assert.Equal(new DateTime(2014, 3, 5, 20, 41, 18, DateTimeKind.Utc), result.TbsResponseData.ProducedAt.ToDateTime());
        }

        [Fact]
        public void VerifyOCSPOfOldEid_Single()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;
            var revocationInfo = new List<BasicOcspResponse>();
            revocationInfo.Add(oldEidOcsp);

            BasicOcspResponse result = target.Verify(issuer, new DateTime(2014, 3, 4, 0, 0, 0, DateTimeKind.Utc), revocationInfo);

            Assert.NotNull(result);
            Assert.Equal(new DateTime(2014, 3, 5, 18, 12, 19, DateTimeKind.Utc), result.TbsResponseData.ProducedAt.ToDateTime());
        }

        [Fact]
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

            Assert.NotNull(result);
            Assert.Equal(DateTime.UtcNow.Floor(), result.TbsResponseData.ProducedAt.ToDateTime().Floor());
        }

        [Fact]
        public void VerifyCrlOfOldEid_NotFound()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            var revocationInfo = new List<CertificateList>();
            revocationInfo.Add(oldEidCrl);

            CertificateList result = target.Verify(issuer, new DateTime(2019, 1, 1, 0, 0, 0, DateTimeKind.Utc), revocationInfo);

            Assert.Null(result);
        }

        [Fact]
        public void VerifyCrlOfOldEid_Valid()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            var revocationInfo = new List<CertificateList>();
            revocationInfo.Add(oldEidCrl);

            CertificateList result = target.Verify(issuer, new DateTime(2016, 6, 16, 8, 14, 8, DateTimeKind.Utc), revocationInfo);

            Assert.NotNull(result);
            Assert.Equal(new DateTime(2018, 7, 16, 8, 14, 8, DateTimeKind.Utc), result.ThisUpdate.ToDateTime());
        }

        [Fact]
        public void VerifyCrlOfOldEid_Revoked()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            var revocationInfo = new List<CertificateList>();
            revocationInfo.Add(oldEidCrl);

            RevocationException<CertificateList> result = Assert.Throws<RevocationException<CertificateList>>(() =>
                target.Verify(issuer, new DateTime(2017, 5, 30, 23, 59, 59, DateTimeKind.Utc), revocationInfo));

            Assert.Equal("The certificate was revoked on 2017-04-27T17:05:15.0000000Z", result.Message);
            Assert.NotNull(result.RevocationInfo);
            Assert.Equal(new DateTime(2018, 7, 16, 8, 14, 8, DateTimeKind.Utc), result.RevocationInfo.ThisUpdate.ToDateTime());
        }

        [Fact]
        public void GetOCSPOfRootCa_NA()
        {
            var target = new X509Certificate2(@"files/belgiumrca4.crt");

            OcspResponse result = target.GetOcspResponse(target);

            Assert.Null(result);
        }

        [Fact]
        public void GetOCSPOfNewEid_Downloaded()
        {
            var target = newEid;
            var issuer = newEidIssuer;

            OcspResponse result = target.GetOcspResponse(issuer);
            BasicOcspResponse resultDetail = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(result.ResponseBytes.Response.GetOctets()));

            Assert.NotNull(result);
            Assert.Equal(0, result.ResponseStatus.IntValueExact);
            Assert.Equal(resultDetail.TbsResponseData.ProducedAt.ToDateTime().Floor(), DateTime.UtcNow.Floor());
        }

        [Fact]
        public async Task GetOCSPOfNewEid_DownloadedAsync()
        {
            var target = newEid;
            var issuer = newEidIssuer;

            OcspResponse result = await target.GetOcspResponseAsync(issuer);
            BasicOcspResponse resultDetail = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(result.ResponseBytes.Response.GetOctets()));

            Assert.NotNull(result);
            Assert.Equal(0, result.ResponseStatus.IntValueExact);
            Assert.Equal(resultDetail.TbsResponseData.ProducedAt.ToDateTime().Floor(), DateTime.UtcNow.Floor());
        }

        [Fact]
        public void GetOCSPOfOldEid_Failed()
        {
            var target = oldEid;
            var issuer = oldEidIssuer;

            Assert.Throws<RevocationUnknownException>(() => target.GetOcspResponse(target));
        }

        [Fact]
        public void GetOCSPOfGoogle_Downloaded()
        {
            var target = new X509Certificate2(@"files/google.crt");
            var issuer = new X509Certificate2(@"files/GTSCA.crt");

            Assert.Throws<RevocationUnknownException>(() => target.GetOcspResponse(issuer));
        }

        [Fact]
        public void GetOCSPOfEgelke_Downloaded()
        {
            var target = new X509Certificate2(@"files/egelke.crt");
            var issuer = new X509Certificate2(@"files/sentigoCA.cer");

            OcspResponse result = target.GetOcspResponse(issuer);
            BasicOcspResponse resultDetail = BasicOcspResponse.GetInstance(Asn1Object.FromByteArray(result.ResponseBytes.Response.GetOctets()));

            Assert.NotNull(result);
            Assert.Equal(0, result.ResponseStatus.IntValueExact);
            Assert.True(resultDetail.TbsResponseData.ProducedAt.ToDateTime() <= DateTime.UtcNow);
        }

        [Fact]
        public void GetCertificateListOfRootCa_NA()
        {
            var target = new X509Certificate2(@"files/belgiumrca4.crt");

            CertificateList result = target.GetCertificateList();

            Assert.Null(result);
        }

        [Fact]
        public void GetCertificateListOfNewEid_Downloaded()
        {
            var target = newEid;

            CertificateList result = target.GetCertificateList();

            Assert.NotNull(result);
            Assert.True(result.ThisUpdate.ToDateTime() <= DateTime.UtcNow);
            Assert.True(result.NextUpdate.ToDateTime() >= DateTime.UtcNow);
        }

        [Fact]
        public async Task GetCertificateListOfNewEid_DownloadedAsync()
        {
            var target = newEid;

            CertificateList result = await target.GetCertificateListAsync();

            Assert.NotNull(result);
            Assert.True(result.ThisUpdate.ToDateTime() <= DateTime.UtcNow);
            Assert.True(result.NextUpdate.ToDateTime() >= DateTime.UtcNow);
        }

        [Fact]
        public void GetCertificateListWithMulti_DownloadedFirst()
        {
            var target = new X509Certificate2(@"files/linuxize.crt");

            CertificateList result = target.GetCertificateList();

            Assert.NotNull(result);
            Assert.True(result.ThisUpdate.ToDateTime() <= DateTime.UtcNow);
            Assert.True(result.NextUpdate.ToDateTime() >= DateTime.UtcNow);
        }



    }
}