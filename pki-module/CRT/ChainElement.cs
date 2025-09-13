/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014-2015 Egelke BVBA
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
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// An element in the Chain of certificates with their status.
    /// </summary>
    public class ChainElement
    {
        /// <summary>
        /// Default constructor, no cert and empty status list.
        /// </summary>
        public ChainElement()
        {
            this.ChainElementStatus = new List<X509ChainStatus>();
        }

        /// <summary>
        /// Copy constructor, shallow copy of cert and filtered copy of status.
        /// </summary>
        /// <param name="source">Object to cpy from</param>
        internal ChainElement(X509ChainElement source)
            : this()
        {
            this.Certificate = source.Certificate;
            this.ChainElementStatus.AddRange(source.ChainElementStatus.Where(x => 
                x.Status != X509ChainStatusFlags.OfflineRevocation
                && x.Status !=  X509ChainStatusFlags.RevocationStatusUnknown
                && x.Status != X509ChainStatusFlags.Revoked));
        }

        /// <summary>
        /// The certificate.
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// The list of validation status flags.
        /// </summary>
        public List<X509ChainStatus> ChainElementStatus { get; set; }
    }

    
}
