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
    /// Class to activate ECDSA with CryptoConfig.
    /// </summary>
    public class ECDSAConfig
    {
        static ECDSAConfig()
        {
            CryptoConfig.AddAlgorithm(typeof(ECDSASignatureFormatter), nameof(ECDSASignatureFormatter));
            CryptoConfig.AddAlgorithm(typeof(ECDSASignatureDeformatter), nameof(ECDSASignatureDeformatter));
            CryptoConfig.AddAlgorithm(typeof(ECDSASha1SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
            CryptoConfig.AddAlgorithm(typeof(ECDSASha256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
            CryptoConfig.AddAlgorithm(typeof(ECDSASha384SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384");
            CryptoConfig.AddAlgorithm(typeof(ECDSASha512SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
        }

        /// <summary>
        /// Method to activate the ECDSA for xml usage.
        /// </summary>
        /// <remarks>
        /// This method is safe to be called multiple times.
        /// </remarks>
        public static void Init()
        {
            //invoke the static constuctor.
        }

    }
}
