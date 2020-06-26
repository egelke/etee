using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using BC = Org.BouncyCastle;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    public static class AsymmetricAlgorithmExtensions
    {
        public static byte[] GetSubjectKeyIdentifier(this AsymmetricAlgorithm key)
        {
            var ski = new SubjectKeyIdentifierStructure(key.ToAsymmetricKeyParameter());
            return ski.GetKeyIdentifier();
        }

        public static List<X509SubjectKeyIdentifierExtension> ToList(this X509ExtensionCollection collection)
        {
            var list = new List<X509SubjectKeyIdentifierExtension>();
            for (int i = 0; i < collection.Count; i++)
            {
                list.Add(collection[i] as X509SubjectKeyIdentifierExtension);
            }
            return list;
        }

        public static AsymmetricKeyParameter ToAsymmetricKeyParameter(this AsymmetricAlgorithm key)
        {
            if (key == null)
            {
                return null;
            }

            BC::Crypto.AsymmetricKeyParameter bcKey;
            if (key is RSA)
                bcKey = DotNetUtilities.GetRsaPublicKey((RSA)key);
            else if (key is DSA)
                bcKey = DotNetUtilities.GetDsaPublicKey((DSA)key);
            else
                throw new ArgumentException("Only RSA and DSA keys supported", "key");

            return bcKey;
        }

        public static AsymmetricAlgorithm ToAsymmetricAlgorithm(this string asymmetricAlgorithmKeyString)
        {
            //TODO for DSA?
            //todo maybe this?
            //var possibleKey = PublicKeyFactory.CreateKey(Convert.FromBase64String(asymmetricAlgorithmKeyString));
            if (asymmetricAlgorithmKeyString == null)
            {
                return null;
            }

            TextReader reader = new StringReader(asymmetricAlgorithmKeyString);
            PemReader pemReader = new PemReader(reader);

            object result = pemReader.ReadObject();

            if (result is AsymmetricCipherKeyPair)
            {
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)result;
                return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
            }
            else if (result is RsaKeyParameters)
            {
                RsaKeyParameters keyParameters = (RsaKeyParameters)result;
                return DotNetUtilities.ToRSA(keyParameters);
            }

            throw new Exception("Unepxected PEM type");

        }

    }
}
