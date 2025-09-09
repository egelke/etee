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
    /// The chain of certificates, from end to root.
    /// </summary>
    public class Chain
    {
        /// <summary>
        /// Default constructor, creates an empty chain.
        /// </summary>
        public Chain()
        {
            ChainElements = new List<ChainElement>();
            ChainStatus = new List<X509ChainStatus>();
        }

        /// <summary>
        /// The elements of the chain
        /// </summary>
        public List<ChainElement> ChainElements { get; }

        /// <summary>
        /// The status of the chain itself.
        /// </summary>
        /// <remarks>
        /// This includes the "summary" of the chain element statuses.
        /// </remarks>
        public List<X509ChainStatus> ChainStatus { get; }

        /// <summary>
        /// Get the lowed NotAfter time of all chain elements
        /// </summary>
        /// <returns>The lowest time, or <c>DateTime.MavValue</c> if no elements in the chain</returns>
        public DateTime GetMinNotAfter()
        {
            DateTime min = DateTime.MaxValue;
            foreach (ChainElement chainE in ChainElements)
            {
                DateTime end = chainE.Certificate.NotAfter.ToUniversalTime();
                if (end < min)
                {
                    min = end;
                }
            }
            return min;
        }
    }
}
