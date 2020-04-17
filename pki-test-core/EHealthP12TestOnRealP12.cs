using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections;
using Egelke.EHealth.Client.Pki;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Runtime.InteropServices;

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestClass]
    public class EHealthP12TestOnRealP12
    {
        private static EHealthP12 p12;

        [ClassInitialize]
        public static void setup(TestContext ctx)
        {
            p12 = new EHealthP12(@"EHealthP12\eHealth.acc-p12", File.ReadAllText(@"EHealthP12\eHealth.acc-p12.pwd"));
        }

        [TestMethod]
        public void AuthValue()
        {
            X509Certificate2 cert = p12["authentication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA rsaPrivateKey = (RSA)cert.PrivateKey;
            byte[] signature = rsaPrivateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsNotNull(signature);
            Assert.AreEqual(2048 / 8, signature.Length);

            RSA rsaPublicKey = (RSA)cert.PublicKey.Key;
            Assert.IsTrue(rsaPublicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [TestMethod]
        public void EncValue()
        {
            X509Certificate2 auth = p12["authentication"];
            string key = p12.Where(e => e.Value.Issuer == auth.Subject).Select(e => e.Key).FirstOrDefault();
            X509Certificate2 cert = p12[key];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA publicKey = (RSA)cert.PublicKey.Key;
            byte[] enc = publicKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            Assert.IsNotNull(enc);

            RSA privateKey = (RSA)cert.PrivateKey;
            byte[] data_copy = privateKey.Decrypt(enc, RSAEncryptionPadding.Pkcs1);
            Assert.AreEqual(data.Length, data_copy.Length);
            for (int i = 0; i < data.Length; i++)
            {
                Assert.AreEqual(data[i], data_copy[i]);
            }
        }

        [TestMethod]
        public void ReinstallInCurrentUser()
        {
            //Prepare
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadWrite);
            X509Store cas = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            cas.Open(OpenFlags.ReadWrite);
            X509Store root = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            root.Open(OpenFlags.ReadWrite);
            foreach (X509Certificate2 cert in p12.Values)
            {
                if (my.Certificates.Contains(cert))
                    my.Remove(cert);
                if (cas.Certificates.Contains(cert))
                    cas.Remove(cert);
                if (root.Certificates.Contains(cert))
                    root.Remove(cert);
            }

            //Test install
            p12.Install(StoreLocation.CurrentUser);
        }

    }
}
