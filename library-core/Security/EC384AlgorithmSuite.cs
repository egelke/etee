/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
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
using System.Runtime.ConstrainedExecution;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;
using Egelke.EHealth.Client.Pki.ECDSA;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom WCF Algorithm suite that supports EC certificates
    /// </summary>
    /// <remarks>
    /// Also initializes the required ECDSA config.
    /// </remarks>
    public class EC384AlgorithmSuite : SecurityAlgorithmSuite
    {
        /// <summary>
        /// Singleton instance.
        /// </summary>
        public static readonly EC384AlgorithmSuite EC384 = new EC384AlgorithmSuite();

        /// <summary>
        /// Base constructor, initializes 
        /// </summary>
        public EC384AlgorithmSuite() : base() {
            ECDSAConfig.Init();
        }

        /// <summary>
        /// Default C14N = xml-enc-c14n
        /// </summary>
        public override string DefaultCanonicalizationAlgorithm { get { return "http://www.w3.org/2001/10/xml-exc-c14n#"; } }

        /// <summary>
        /// Default digest = sha256
        /// </summary>
        public override string DefaultDigestAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#sha256"; } }

        /// <summary>
        /// Default encryption = AES256-cbc
        /// </summary>
        public override string DefaultEncryptionAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#aes256-cbc"; } }

        /// <summary>
        /// Default encryption derivation length = 256;
        /// </summary>
        public override int DefaultEncryptionKeyDerivationLength { get { return 256; } }

        /// <summary>
        /// Default Sym key wrapper algo = KW AES256
        /// </summary>
        public override string DefaultSymmetricKeyWrapAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#kw-aes256"; } }

        /// <summary>
        /// Default Asym Key Wrapper aglo = RSA OAEP MGF 1P
        /// </summary>
        public override string DefaultAsymmetricKeyWrapAlgorithm { get { return "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"; } }

        /// <summary>
        /// Default Sym Sign Algo = HMAC(SHA256)
        /// </summary>
        public override string DefaultSymmetricSignatureAlgorithm { get { return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"; } }

        /// <summary>
        /// Default Asym Sign Algo = ECDSA-SHA256
        /// </summary>
        public override string DefaultAsymmetricSignatureAlgorithm { get { return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"; } }

        /// <summary>
        /// Default Sign Key Derivation Length = 192
        /// </summary>
        public override int DefaultSignatureKeyDerivationLength { get { return 192; } }

        /// <summary>
        /// Default Sym Key Length = 256
        /// </summary>
        public override int DefaultSymmetricKeyLength { get { return 256; } }

        /// <summary>
        /// Checks if Sym key length is supported (only 256 is)
        /// </summary>
        /// <param name="length">length to check, must be 256</param>
        /// <returns>true if supported</returns>
        public override bool IsSymmetricKeyLengthSupported(int length) { return length == 256; }

        /// <summary>
        /// Checks if Asym Key length is supported (between 1Ki and 4Ki)
        /// </summary>
        /// <param name="length">length to check, must be between 1024 and 4096</param>
        /// <returns>true if supported</returns>
        public override bool IsAsymmetricKeyLengthSupported(int length) { return length >= 1024 && length <= 4096; }

        /// <summary>
        /// Returns its ID string.
        /// </summary>
        /// <returns>The value EC384</returns>
        public override string ToString()
        {
            return "EC384";
        }
    }
}
