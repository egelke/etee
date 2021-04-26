using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Egelke.EHealth.Client.Sso.Helper
{
    public class ECDSASignatureFormatter : AsymmetricSignatureFormatter
    {
        private ECDsa _key;

        public ECDSASignatureFormatter()
        {

        }

        public override byte[] CreateSignature(byte[] rgbHash)
        {
            if (rgbHash == null)
                throw new ArgumentNullException("rgbHash");

            if (_key == null)
                throw new CryptographicUnexpectedOperationException("Cryptography MissingKey");

            return _key.SignHash(rgbHash);
        }

        public override void SetHashAlgorithm(string strName)
        {
            //does it really matter?
        }

        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            _key = (ECDsa)key;
        }
    }
}
