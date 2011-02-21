/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Client.Tool;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Siemens.eHealth.ETEE.Crypto.Test;
using System.Collections;

namespace Siemens.EHealth.Client.UnitTest
{
    [TestClass]
    public class EHealthP12TestOnDummy
    {
        EHealthP12 p12;

        [TestInitialize]
        public void setup()
        {
            p12 = new EHealthP12("dummy.p12", "test001");
        }

        [TestMethod]
        public void ConstuctorWithByteArray()
        {
            p12 = new EHealthP12(Utils.ReadFully("dummy.p12"), "test001");
            Assert.AreEqual(2, p12.Keys.Count);
        }

        [TestMethod]
        public void Keys()
        {
            Assert.AreEqual(2, p12.Keys.Count);
            Assert.IsTrue(p12.Keys.Contains("authenication"));
            Assert.IsTrue(p12.Keys.Contains("encryption"));
            Assert.IsFalse(p12.Keys.Contains("security"));
        }

        [TestMethod]
        public void Values()
        {
            Assert.AreEqual(2, p12.Values.Count);
            foreach (X509Certificate2 cert in p12.Values)
            {
                switch (cert.Subject)
                {
                    case "CN=cert2, O=Internet Widgits Pty Ltd, S=Some-State, C=AU":
                    case "CN=cert1, O=Internet Widgits Pty Ltd, S=Some-State, C=AU":
                        Assert.IsTrue(cert.HasPrivateKey);
                        break;
                    default:
                        Assert.Fail(cert.Subject);
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

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            byte[] signature = privateKey.SignData(data, new SHA1Managed());
            Assert.IsNotNull(signature);
            Assert.AreEqual(1024/8, signature.Length);

            RSACryptoServiceProvider publicKey =  cert.PublicKey.Key as RSACryptoServiceProvider;
            Assert.IsTrue(publicKey.VerifyData(data, new SHA1Managed(), signature));
        }

        [TestMethod]
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

        [TestMethod]
        [ExpectedException(typeof(KeyNotFoundException))]
        public void NonExistingValue()
        {
            X509Certificate2 cert = p12["other"];
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void ContainsKeyWihtNullValue()
        {
            p12.ContainsKey(null);
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
            Assert.AreEqual(2, p12.Count);
        }

        [TestMethod]
        public void IsReadOnly()
        {
            Assert.IsTrue(p12.IsReadOnly);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void CopyToNull()
        {
            p12.CopyTo(null, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentOutOfRangeException))]
        public void CopyToNegativeIndex()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[0];
            p12.CopyTo(array, -1);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void CopyToArrayThatIsToSmall()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[3];
            p12.CopyTo(array, 2);
        }

        [TestMethod]
        public void CopyTo()
        {
            KeyValuePair<String, X509Certificate2> def = new KeyValuePair<String, X509Certificate2>();
            KeyValuePair<String, X509Certificate2>[] array =new KeyValuePair<string, X509Certificate2>[4];
            p12.CopyTo(array, 1);
            Assert.AreEqual(def, array[0]);
            Assert.AreNotEqual(def, array[1]);
            Assert.AreNotEqual(def, array[2]);
            Assert.AreEqual(def, array[3]);
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
                        Assert.Fail(entry.Key);
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
                        Assert.Fail(entry.Key);
                        break;
                }
            }
        }
    }
}
