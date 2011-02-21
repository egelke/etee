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
    public class EHealthP12TestOnRealP12
    {
        private static EHealthP12 p12;

        [ClassInitialize]
        public static void setup(TestContext context)
        {
            X509Certificate2 cert;
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                cert = my.Certificates.Find(X509FindType.FindByThumbprint, "cf692e24bac7c1d990496573e64ef999468be67e", false)[0];
            }
            finally
            {
                my.Close();
            }

            RSACryptoServiceProvider key = (RSACryptoServiceProvider)cert.PrivateKey;
            String pwd = Encoding.UTF8.GetString(key.Decrypt(Convert.FromBase64String(Properties.Settings.Default.RealP12Pwd), true));

            p12 = new EHealthP12("SSIN=79021802145.p12", pwd);
        }

        [TestMethod]
        public void AuthValue()
        {
            X509Certificate2 cert = p12["authentication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            byte[] signature = privateKey.SignData(data, new SHA1Managed());
            Assert.IsNotNull(signature);
            Assert.AreEqual(2048/8, signature.Length);

            RSACryptoServiceProvider publicKey =  cert.PublicKey.Key as RSACryptoServiceProvider;
            Assert.IsTrue(publicKey.VerifyData(data, new SHA1Managed(), signature));
        }

        [TestMethod]
        public void EncValue()
        {
            X509Certificate2 cert = p12["111128311597491254660610152441480790885"];
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
       
    }
}
