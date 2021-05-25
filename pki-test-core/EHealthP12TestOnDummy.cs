
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestClass]
    public class EHealthP12TestOnDummy
    {
        private static EHealthP12 p12;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void setupClass(TestContext ctx)
        {
            p12 = new EHealthP12(@"EHealthP12/dummy.p12", "test001");
        }

        [TestMethod]
        public void ConstuctorWithByteArray()
        {
            p12 = new EHealthP12(File.ReadAllBytes(@"EHealthP12/dummy.p12"), "test001");
            Assert.AreEqual(5, p12.Keys.Count);
        }

        [TestMethod]
        public void Keys()
        {
            Assert.AreEqual(5, p12.Keys.Count);
            Assert.IsTrue(p12.Keys.Contains("authenication"));
            Assert.IsTrue(p12.Keys.Contains("encryption"));
            Assert.IsFalse(p12.Keys.Contains("security"));
        }

        [TestMethod]
        public void Values()
        {
            Assert.AreEqual(5, p12.Values.Count);
            foreach (X509Certificate2 cert in p12.Values)
            {
                switch (cert.Subject)
                {
                    case "CN=cert2, O=Internet Widgits Pty Ltd, S=Some-State, C=AU":
                    case "CN=cert1, O=Internet Widgits Pty Ltd, S=Some-State, C=AU":
                        //Assert.IsTrue(cert.HasPrivateKey);
                        break;
                    default:
                        //Assert.IsFalse(cert.HasPrivateKey);
                        break;
                }
            }
        }

        [TestMethod]
        public void AuthValue()
        {
            X509Certificate2 cert = p12["authenication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA privateKey = cert.PrivateKey as RSA;
            byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.IsNotNull(signature);
            Assert.AreEqual(1024/8, signature.Length);

            RSA publicKey =  cert.PublicKey.Key as RSA;
            Assert.IsTrue(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [TestMethod]
        public void EncValue()
        {
            X509Certificate2 cert = p12["encryption"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA publicKey = cert.PublicKey.Key as RSA;
            byte[] enc = publicKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            Assert.IsNotNull(enc);

            RSA privateKey = cert.PrivateKey as RSA;
            byte[] data_copy = privateKey.Decrypt(enc, RSAEncryptionPadding.Pkcs1);
            Assert.AreEqual(data.Length,data_copy.Length);
            for (int i=0; i<data.Length; i++)
            {
                Assert.AreEqual(data[i], data_copy[i]);
            }
        }

        [TestMethod]
        public void NonExistingValue()
        {
            Assert.ThrowsException<KeyNotFoundException>(() => p12["other"]);
        }

        [TestMethod]
        public void ContainsKeyWihtNullValue()
        {
            Assert.ThrowsException<ArgumentNullException>(() => p12.ContainsKey(null));
        }

        [TestMethod]
        public void ContainsKey()
        {
            Assert.IsFalse(p12.ContainsKey("other"));
            Assert.IsTrue(p12.ContainsKey("encryption"));
        }

        [TestMethod]
        public void TryGetValue()
        {
            X509Certificate2 cert;

            Assert.IsTrue(p12.TryGetValue("authenication", out cert));
            Assert.AreEqual("CN=cert1, O=Internet Widgits Pty Ltd, S=Some-State, C=AU", cert.Subject);
            Assert.IsFalse(p12.TryGetValue("other", out cert));
            Assert.IsNull(cert);
        }

        [TestMethod]
        public void Count()
        {
            Assert.AreEqual(5, p12.Count);
        }

        [TestMethod]
        public void IsReadOnly()
        {
            Assert.IsTrue(p12.IsReadOnly);
        }

        [TestMethod]
        public void CopyToNull()
        {
            Assert.ThrowsException<ArgumentNullException>(() => p12.CopyTo(null, 0));
        }

        [TestMethod]
        public void CopyToNegativeIndex()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[0];
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => p12.CopyTo(array, -1));
        }

        [TestMethod]
        public void CopyToArrayThatIsToSmall()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[3];
            Assert.ThrowsException<ArgumentException>(() => p12.CopyTo(array, 2));
        }

        [TestMethod]
        public void CopyTo()
        {
            KeyValuePair<String, X509Certificate2> def = new KeyValuePair<String, X509Certificate2>();
            KeyValuePair<String, X509Certificate2>[] array =new KeyValuePair<string, X509Certificate2>[7];
            p12.CopyTo(array, 1);
            Assert.AreEqual(def, array[0]);
            Assert.AreNotEqual(def, array[1]);
            Assert.AreNotEqual(def, array[2]);
            Assert.AreNotEqual(def, array[3]);
            Assert.AreNotEqual(def, array[4]);
            Assert.AreNotEqual(def, array[5]);
            Assert.AreEqual(def, array[6]);
        }

        [TestMethod]
        public void ToCollection()
        {
            X509Certificate2Collection collection = p12.ToCollection();
            Assert.AreEqual(5, collection.Count);
        }

        [TestMethod]
        public void ForEach()
        {
            foreach (KeyValuePair<String, X509Certificate2> entry in p12)
            {
                switch (entry.Key)
                {
                    case "authenication":
                    case "encryption":
                        Assert.IsTrue(entry.Value.HasPrivateKey);
                        break;
                    default:
                        Assert.IsFalse(entry.Value.HasPrivateKey);
                        break;
                }
            }
        }

        [TestMethod]
        public void ForEachAsIEnumerable()
        {
            foreach (Object o in ((IEnumerable) p12))
            {
                KeyValuePair<String, X509Certificate2> entry = (KeyValuePair<String, X509Certificate2>)o;
                switch (entry.Key)
                {
                    case "authenication":
                    case "encryption":
                        Assert.IsTrue(entry.Value.HasPrivateKey);
                        break;
                    default:
                        Assert.IsFalse(entry.Value.HasPrivateKey);
                        break;
                }
            }
        }
    }
}
