
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections;
using NUnit.Framework;
using System.IO;

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestFixture]
    public class EHealthP12TestOnDummy
    {
        EHealthP12 p12;

        [TestFixtureSetUp]
        public void setup()
        {
            p12 = new EHealthP12(@"..\..\EHealthP12\dummy.p12", "test001");
        }

        [Test]
        public void ConstuctorWithByteArray()
        {
            p12 = new EHealthP12(File.ReadAllBytes(@"..\..\EHealthP12\dummy.p12"), "test001");
            Assert.AreEqual(5, p12.Keys.Count);
        }

        [Test]
        public void Keys()
        {
            Assert.AreEqual(5, p12.Keys.Count);
            Assert.IsTrue(p12.Keys.Contains("authenication"));
            Assert.IsTrue(p12.Keys.Contains("encryption"));
            Assert.IsFalse(p12.Keys.Contains("security"));
        }

        [Test]
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

        [Test]
        public void AuthValue()
        {
            X509Certificate2 cert = p12["authenication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            byte[] signature = privateKey.SignData(data, new SHA1Managed());
            Assert.IsNotNull(signature);
            Assert.AreEqual(1024/8, signature.Length);

            RSACryptoServiceProvider publicKey =  cert.PublicKey.Key as RSACryptoServiceProvider;
            Assert.IsTrue(publicKey.VerifyData(data, new SHA1Managed(), signature));
        }

        [Test]
        public void EncValue()
        {
            X509Certificate2 cert = p12["encryption"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider publicKey = cert.PublicKey.Key as RSACryptoServiceProvider;
            byte[] enc = publicKey.Encrypt(data, false);
            Assert.IsNotNull(enc);

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            byte[] data_copy = privateKey.Decrypt(enc, false);
            Assert.AreEqual(data.Length,data_copy.Length);
            for (int i=0; i<data.Length; i++)
            {
                Assert.AreEqual(data[i], data_copy[i]);
            }
        }

        [Test]
        [ExpectedException(typeof(KeyNotFoundException))]
        public void NonExistingValue()
        {
            X509Certificate2 cert = p12["other"];
        }

        [Test]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ContainsKeyWihtNullValue()
        {
            p12.ContainsKey(null);
        }

        [Test]
        public void ContainsKey()
        {
            Assert.IsFalse(p12.ContainsKey("other"));
            Assert.IsTrue(p12.ContainsKey("encryption"));
        }

        [Test]
        public void TryGetValue()
        {
            X509Certificate2 cert;

            Assert.IsTrue(p12.TryGetValue("authenication", out cert));
            Assert.AreEqual("CN=cert1, O=Internet Widgits Pty Ltd, S=Some-State, C=AU", cert.Subject);
            Assert.IsFalse(p12.TryGetValue("other", out cert));
            Assert.IsNull(cert);
        }

        [Test]
        public void Count()
        {
            Assert.AreEqual(5, p12.Count);
        }

        [Test]
        public void IsReadOnly()
        {
            Assert.IsTrue(p12.IsReadOnly);
        }

        [Test]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CopyToNull()
        {
            p12.CopyTo(null, 0);
        }

        [Test]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void CopyToNegativeIndex()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[0];
            p12.CopyTo(array, -1);
        }

        [Test]
        [ExpectedException(typeof(ArgumentException))]
        public void CopyToArrayThatIsToSmall()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[3];
            p12.CopyTo(array, 2);
        }

        [Test]
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

        [Test]
        public void ToCollection()
        {
            X509Certificate2Collection collection = p12.ToCollection();
            Assert.AreEqual(5, collection.Count);
        }

        [Test]
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

        [Test]
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
