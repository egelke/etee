/*
 *  This file is part of eH-I.
 *  Copyright (C) 2021 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Egelke.Wcf.Client.Helper
{
    /// <summary>
    /// Deformatter for ECDSA signatures, used to verify.
    /// </summary>
    public class ECDSASignatureDeformatter : AsymmetricSignatureDeformatter
    {
        private ECDsa _key;

        /// <summary>
        /// Set the hash algorithm used to calculate the hash.
        /// </summary>
        /// <remarks>
        /// Non-op, since DSA doesn't encode the algorithm in the signature like RSA does.
        /// </remarks>
        /// <param name="strName">The algorithm name</param>
        public override void SetHashAlgorithm(string strName)
        {
            //does it really matter?
        }

        /// <summary>
        /// Set the key to use to verify signatures.
        /// </summary>
        /// <param name="key">ECDSA public key</param>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            _key = (ECDsa)key;
        }

        /// <summary>
        /// Verifies if a hash corrersponds with the signatrue of the current key.
        /// </summary>
        /// <param name="rgbHash">The (raw) hash value</param>
        /// <param name="rgbSignature">The signature value</param>
        /// <returns></returns>
        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature)
        {
            return _key.VerifyHash(rgbHash, rgbSignature);
        }
    }
}
