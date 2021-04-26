using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Egelke.EHealth.Client.Sso.Helper
{
    public class ECDSASignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private ECDsa _key;

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

        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            return _key.VerifyHash(rgbHash, rgbSignature);
        }
    }
}
