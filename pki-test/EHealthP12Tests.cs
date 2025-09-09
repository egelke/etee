
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections;
using System.IO;
using Xunit;

namespace Egelke.EHealth.Client.Pki.Test
{
    [Collection("eHealth.acc-p12")]
    public class EHealthP12Tests
    {
        private EHealthP12 dummyP12;
        private readonly EHealthP12 realP12;


        public EHealthP12Tests()
        {
            dummyP12 = new EHealthP12(@"EHealthP12/dummy.p12", "test001");
            realP12 = new EHealthP12(@"files\EHealthP12\eHealth.acc-p12", File.ReadAllText(@"files\EHealthP12\eHealth.acc-p12.pwd"));
        }

        [Fact]
        public void ConstuctorWithByteArray()
        {
            dummyP12 = new EHealthP12(File.ReadAllBytes(@"EHealthP12/dummy.p12"), "test001");
            Assert.Equal(5, dummyP12.Keys.Count);
        }

        [Fact]
        public void Keys()
        {
            Assert.Equal(5, dummyP12.Keys.Count);
            Assert.True(dummyP12.Keys.Contains("authenication"));
            Assert.True(dummyP12.Keys.Contains("encryption"));
            Assert.False(dummyP12.Keys.Contains("security"));
        }

        [Fact]
        public void Values()
        {
            Assert.Equal(5, dummyP12.Values.Count);
            foreach (X509Certificate2 cert in dummyP12.Values)
            {
                switch (cert.Subject)
                {
                    case "CN=cert2, O=Internet Widgits Pty Ltd, S=Some-State, C=AU":
                        Assert.True(cert.HasPrivateKey);
                        break;
                    case "CN=cert1, O=Internet Widgits Pty Ltd, S=Some-State, C=AU":
                        //it can be both, we have it without as CA of the encryption and as auth sign.
                        break;
                    default:
                        Assert.False(cert.HasPrivateKey);
                        break;
                    
                }
            }
        }

        [Fact]
        public void AuthValue()
        {
            X509Certificate2 cert = dummyP12["authenication"];
            Assert.NotNull(cert);
            Assert.True(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA privateKey = cert.GetRSAPrivateKey();
            byte[] signature = privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.NotNull(signature);
            Assert.Equal(1024/8, signature.Length);

            RSA publicKey =  cert.GetRSAPublicKey();
            Assert.True(publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [Fact]
        public void EncValue()
        {
            X509Certificate2 cert = dummyP12["encryption"];
            Assert.NotNull(cert);
            Assert.True(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA publicKey = cert.GetRSAPublicKey();
            byte[] enc = publicKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            Assert.NotNull(enc);

            RSA privateKey = cert.GetRSAPrivateKey();
            byte[] data_copy = privateKey.Decrypt(enc, RSAEncryptionPadding.Pkcs1);
            Assert.Equal(data.Length,data_copy.Length);
            for (int i=0; i<data.Length; i++)
            {
                Assert.Equal(data[i], data_copy[i]);
            }
        }

        [Fact]
        public void NonExistingValue()
        {
            Assert.Throws<KeyNotFoundException>(() => dummyP12["other"]);
        }

        [Fact]
        public void ContainsKeyWihtNullValue()
        {
            Assert.Throws<ArgumentNullException>(() => dummyP12.ContainsKey(null));
        }

        [Fact]
        public void ContainsKey()
        {
            Assert.False(dummyP12.ContainsKey("other"));
            Assert.True(dummyP12.ContainsKey("encryption"));
        }

        [Fact]
        public void TryGetValue()
        {
            Assert.True(dummyP12.TryGetValue("authenication", out X509Certificate2 cert));
            Assert.Equal("CN=cert1, O=Internet Widgits Pty Ltd, S=Some-State, C=AU", cert.Subject);
            Assert.False(dummyP12.TryGetValue("other", out cert));
            Assert.Null(cert);
        }

        [Fact]
        public void Count()
        {
            Assert.Equal(5, dummyP12.Count);
        }

        [Fact]
        public void IsReadOnly()
        {
            Assert.True(dummyP12.IsReadOnly);
        }

        [Fact]
        public void CopyToNull()
        {
            Assert.Throws<ArgumentNullException>(() => dummyP12.CopyTo(null, 0));
        }

        [Fact]
        public void CopyToNegativeIndex()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[0];
            Assert.Throws<ArgumentOutOfRangeException>(() => dummyP12.CopyTo(array, -1));
        }

        [Fact]
        public void CopyToArrayThatIsToSmall()
        {
            KeyValuePair<String, X509Certificate2>[] array = new KeyValuePair<string, X509Certificate2>[3];
            Assert.Throws<ArgumentException>(() => dummyP12.CopyTo(array, 2));
        }

        [Fact]
        public void CopyTo()
        {
            KeyValuePair<String, X509Certificate2> def = new KeyValuePair<String, X509Certificate2>();
            KeyValuePair<String, X509Certificate2>[] array =new KeyValuePair<string, X509Certificate2>[7];
            dummyP12.CopyTo(array, 1);
            Assert.Equal(def, array[0]);
            Assert.NotEqual(def, array[1]);
            Assert.NotEqual(def, array[2]);
            Assert.NotEqual(def, array[3]);
            Assert.NotEqual(def, array[4]);
            Assert.NotEqual(def, array[5]);
            Assert.Equal(def, array[6]);
        }

        [Fact]
        public void ToCollection()
        {
            X509Certificate2Collection collection = dummyP12.ToCollection();
            Assert.Equal(5, collection.Count);
        }

        [Fact]
        public void ForEach()
        {
            foreach (KeyValuePair<String, X509Certificate2> entry in dummyP12)
            {
                switch (entry.Key)
                {
                    case "authenication":
                    case "encryption":
                        Assert.True(entry.Value.HasPrivateKey);
                        break;
                    default:
                        Assert.False(entry.Value.HasPrivateKey);
                        break;
                }
            }
        }

        [Fact]
        public void ForEachAsIEnumerable()
        {
            foreach (Object o in ((IEnumerable) dummyP12))
            {
                KeyValuePair<String, X509Certificate2> entry = (KeyValuePair<String, X509Certificate2>)o;
                switch (entry.Key)
                {
                    case "authenication":
                    case "encryption":
                        Assert.True(entry.Value.HasPrivateKey);
                        break;
                    default:
                        Assert.False(entry.Value.HasPrivateKey);
                        break;
                }
            }
        }

        [Fact]
        public void RealAuthValue()
        {
            X509Certificate2 cert = realP12["authentication"];
            Assert.NotNull(cert);
            Assert.True(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            
            RSA rsaPublicKey = cert.GetRSAPublicKey();
            if (rsaPublicKey != null)
            {
                RSA rsaPrivateKey = cert.GetRSAPrivateKey();
                byte[] signature = rsaPrivateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.NotNull(signature);
                Assert.Equal(2048 / 8, signature.Length);

                Assert.True(rsaPublicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }

            
            ECDsa ecPublicKey = cert.GetECDsaPublicKey();
            if (ecPublicKey != null)
            {
                ECDsa ecPrivateKey = cert.GetECDsaPrivateKey();
                byte[] signature = ecPrivateKey.SignHash(data); //hashing is more a convention then a requirement, the signature will do it anyway
                Assert.NotNull(signature);

                Assert.True(ecPublicKey.VerifyHash(data, signature));
            }
        }



        [Fact]
        public void RealEncValue()
        {
            X509Certificate2 auth = realP12["authentication"];
            string key = realP12.Where(e => e.Value.Issuer == auth.Subject).Select(e => e.Key).FirstOrDefault();
            X509Certificate2 cert = realP12[key];
            Assert.NotNull(cert);
            Assert.True(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSA publicKey = cert.GetRSAPublicKey();
            byte[] enc = publicKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            Assert.NotNull(enc);

            RSA privateKey = cert.GetRSAPrivateKey();
            byte[] data_copy = privateKey.Decrypt(enc, RSAEncryptionPadding.Pkcs1);
            Assert.Equal(data.Length, data_copy.Length);
            for (int i = 0; i < data.Length; i++)
            {
                Assert.Equal(data[i], data_copy[i]);
            }
        }

        /*
        [Fact]
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
        */
    }
}
