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

namespace Egelke.EHealth.Client.Pki.ECDSA
{
    /// <summary>
    /// ECDSA signature formatter, used to sign with ECDA key.
    /// </summary>
    public class ECDSASignatureFormatter : AsymmetricSignatureFormatter
    {
        private ECDsa _key;

        /// <summary>
        /// Default constructor.
        /// </summary>
        public ECDSASignatureFormatter()
        {

        }

        /// <summary>
        /// Sign the provided hash with the current key
        /// </summary>
        /// <param name="rgbHash">The (raw) hash to sign</param>
        /// <returns>The singature</returns>
        /// <exception cref="ArgumentNullException">when rgbHash is null</exception>
        /// <exception cref="CryptographicUnexpectedOperationException">when the private key isn't set</exception>
        public override byte[] CreateSignature(byte[] rgbHash)
        {
            if (rgbHash == null)
                throw new ArgumentNullException("rgbHash");

            if (_key == null)
                throw new CryptographicUnexpectedOperationException("Cryptography MissingKey");

            return _key.SignHash(rgbHash);
        }

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
        /// Set the key to use to calculate signatures.
        /// </summary>
        /// <param name="key">ECDSA private key</param>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            _key = (ECDsa)key;
        }
    }
}
