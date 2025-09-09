/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
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
    /// Object representation of an RFC3161 token.
    /// </summary>
    public class Timestamp
    {
        /// <summary>
        /// The time specified by the timestamp.
        /// </summary>
        public DateTime Time { get; set; }

        /// <summary>
        /// The moment when the timestamp may no longer be verifiable.
        /// </summary>
        /// <remarks>
        /// This is the lower bound value, it still might be possible
        /// to validate the timestamp depending on TSA.
        /// This value is calculated based on the certificate chain
        /// of the timestamp.
        /// </remarks>
        public DateTime RenewalTime { get; set; }

        /// <summary>
        /// The status of the timestamp.
        /// </summary>
        /// <remarks>
        /// This is a "summary" of the certificate chain status.
        /// </remarks>
        public List<X509ChainStatus> TimestampStatus { get; set; }

        /// <summary>
        /// The chain of the certificates used to sign the timestamp.
        /// </summary>
        public Chain CertificateChain { get; set; }
    }
}
