/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014-2020 Egelke
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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Egelke.EHealth.Etee.Crypto.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509.Extension;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>
    /// Represents an asymetic key or Web Authentication.
    /// </summary>
    public class WebKey
    {
        private static AsymmetricKeyParameter ToBCPublicKey(AsymmetricAlgorithm key)
        {
            if (key is DSA)
            {
                return DotNetUtilities.GetDsaPublicKey((DSA)key);
            }

            if (key is RSA)
            {
                return DotNetUtilities.GetRsaPublicKey((RSA)key);
            }

            throw new ArgumentException("Unsupported algorithm specified", "privateKey");
        }

        private AsymmetricAlgorithm key;

        /// <summary>
        /// Constructor for the Object representation of the WebKey.
        /// </summary>
        public WebKey(AsymmetricAlgorithm key)
        {
            this.Id = new SubjectKeyIdentifierStructure(ToBCPublicKey(key)).GetKeyIdentifier();
            this.key = key;
        }

        /* TODO::When activate when we know the format the public key service returns.
        /// <summary>
        /// Constructor for the string representation of the WebKey.
        /// </summary>
        /// <param name="id">The ID of the WebKey, normally the Subject Key Identifier.</param>
        /// <param name="key">The WebKey itself</param>
        public WebKey(String id, AsymmetricAlgorithm key)
            : this(Convert.FromBase64String(id), key)
        {

        }
        */

        /// <summary>
        /// Constructor for the Object representation of the WebKey.
        /// </summary>
        /// <param name="id">The ID of the WebKey, normally the Subject Key Identifier.</param>
        /// <param name="key">The WebKey itself</param>
        public WebKey(byte[] id, AsymmetricAlgorithm key)
        {
            this.Id = id;
            this.key = key;
        }


        /// <summary>
        /// The binary form of the WebKey id.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the only part of the WebKey that the application itself must transmit to the receiver,
        /// together with the message itself.  This is public information, so there is no need to seal it
        /// for transport.
        /// </para>
        /// <para>
        /// Use this representation of the WebKey id if the transport support binary information.
        /// </para>
        /// </remarks>
        public byte[] Id { get;  }

        /// <summary>
        /// The string form of the WebKey id.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the only part of the WebKey that the application itself must transmit to the receiver,
        /// together with the message itself.  This is public information, so there is no need to seal it
        /// for transport.
        /// </para>
        /// <para>
        /// Use this representation of the WebKey id if the transport only support text information.
        /// </para>
        /// </remarks>
        public String IdString => Convert.ToBase64String(Id);


        internal AsymmetricCipherKeyPair BCKeyPair => DotNetUtilities.GetKeyPair(key);


        internal AsymmetricKeyParameter BCPublicKey => ToBCPublicKey(key);


    }
}
