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
            String pwd = Microsoft.VisualBasic.Interaction.InputBox("Enther the P12 pwd");

            p12 = new EHealthP12("test.p12", pwd);
            //p12 = new EHealthP12("prod.p12", pwd);
        }

        [TestMethod]
        public void AuthValue()
        {
            X509Certificate2 cert = p12["authentication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            Assert.AreEqual("Microsoft Enhanced RSA and AES Cryptographic Provider", privateKey.CspKeyContainerInfo.ProviderName);
            byte[] signature = privateKey.SignData(data, new SHA1Managed());
            Assert.IsNotNull(signature);
            Assert.AreEqual(2048/8, signature.Length);

            RSACryptoServiceProvider publicKey =  cert.PublicKey.Key as RSACryptoServiceProvider;
            Assert.IsTrue(publicKey.VerifyData(data, new SHA1Managed(), signature));
        }

        [TestMethod]
        public void EncValue()
        {
            X509Certificate2 cert = p12["148459475702464467506498982825636760342"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider publicKey = cert.PublicKey.Key as RSACryptoServiceProvider;
            byte[] enc = publicKey.Encrypt(data, false);
            Assert.IsNotNull(enc);

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            Assert.AreEqual("Microsoft Enhanced RSA and AES Cryptographic Provider", privateKey.CspKeyContainerInfo.ProviderName);
            byte[] data_copy = privateKey.Decrypt(enc, false);
            Assert.AreEqual(data.Length,data_copy.Length);
            for (int i=0; i<data.Length; i++)
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
