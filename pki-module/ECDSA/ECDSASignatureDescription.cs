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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Egelke.EHealth.Client.Pki.ECDSA
{
    /// <summary>
    /// Description for ECDSA signature with any kind of hash function.
    /// </summary>
    public abstract class ECDSASignatureDescription : SignatureDescription
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="digestAlg">The hash function used (must be type or known by CryptoConfig)</param>
        public ECDSASignatureDescription(String digestAlg)
        {
#if NETSTANDARD
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                KeyAlgorithm = typeof(System.Security.Cryptography.ECDsaCng).AssemblyQualifiedName;
            }
            else
            {
                KeyAlgorithm = typeof(System.Security.Cryptography.ECDsaOpenSsl).AssemblyQualifiedName;
            }
#else
            KeyAlgorithm = typeof(System.Security.Cryptography.ECDsaCng).AssemblyQualifiedName;
#endif
            DigestAlgorithm = digestAlg;
            FormatterAlgorithm = nameof(ECDSASignatureFormatter);
            DeformatterAlgorithm = nameof(ECDSASignatureDeformatter);
        }
    }

    /// <summary>
    /// Description for ECDSA signature with SHA1 of hash function.
    /// </summary>
    public class ECDSASha1SignatureDescription : ECDSASignatureDescription
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public ECDSASha1SignatureDescription()
           : base("SHA1")
        {

        }
    }

    /// <summary>
    /// Description for ECDSA signature with SHA256 of hash function.
    /// </summary>
    public class ECDSASha256SignatureDescription : ECDSASignatureDescription
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public ECDSASha256SignatureDescription()
           : base("SHA256")
        {

        }
    }

    /// <summary>
    /// Description for ECDSA signature with SHA384 of hash function.
    /// </summary>
    public class ECDSASha384SignatureDescription : ECDSASignatureDescription
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public ECDSASha384SignatureDescription()
           : base("SHA384")
        {

        }
    }

    /// <summary>
    /// Description for ECDSA signature with SHA512 of hash function.
    /// </summary>
    public class ECDSASha512SignatureDescription : ECDSASignatureDescription
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public ECDSASha512SignatureDescription()
           : base("SHA512")
        {

        }
    }

    
}
