/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using System.IO;
using Org.BouncyCastle.Pkcs;

namespace Siemens.EHealth.Client.Sso
{
    public static class CertGenerator
    {
        private const String p12TmpPwd = "tmp";

        public static X509Certificate2 GenerateSelfSigned(TimeSpan lifetime)
        {
            Guid guid = Guid.NewGuid();
            DateTime now = DateTime.UtcNow;
            SecureRandom rand = new SecureRandom();
            

            //Generate a key pair
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(rand, 1024));
            AsymmetricCipherKeyPair key = keyGen.GenerateKeyPair();

            //Generate a certificate
            X509Name dn = new X509Name("CN=" + guid.ToString());
            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(dn);
            certGen.SetSerialNumber(new BigInteger(1, guid.ToByteArray()));
            certGen.SetSignatureAlgorithm("SHA1WITHRSA");
            certGen.SetSubjectDN(dn);
            certGen.SetPublicKey(key.Public);
            certGen.SetNotBefore(now);
            certGen.SetNotAfter(now.Add(lifetime));
            Org.BouncyCastle.X509.X509Certificate bcCert = certGen.Generate(key.Private);

            //Save it as pkcs12
            MemoryStream p12Stream = new MemoryStream();
            Pkcs12Store p12 = new Pkcs12Store();
            p12.SetKeyEntry("sts", new AsymmetricKeyEntry(key.Private), new X509CertificateEntry[] { new X509CertificateEntry(bcCert) });
            p12.Save(p12Stream, p12TmpPwd.ToCharArray(), rand);

            //Load the pkcs12 as .Net Certificate
            return new X509Certificate2(p12Stream.ToArray(), p12TmpPwd, X509KeyStorageFlags.DefaultKeySet);
        }
    }
}
