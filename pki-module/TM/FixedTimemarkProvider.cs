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
    /// Time-mark provider that always returns the provided time.
    /// </summary>
    /// <remarks>
    /// Should only be used for testing purposes.
    /// </remarks>
    public class FixedTimemarkProvider : ITimemarkProvider
    {
        /// <summary>
        /// The fixed time.
        /// </summary>
        public DateTime Date { get; set; }

        /// <summary>
        /// Create a instance with the fixed time.
        /// </summary>
        /// <param name="date">The fixed time</param>
        public FixedTimemarkProvider(DateTime date)
        {
            this.Date = date;
        }

        /// <summary>
        /// Simply returns the fixed time.
        /// </summary>
        /// <param name="sender">Ignored</param>
        /// <param name="signingTime">Ignored</param>
        /// <param name="signatureValue">Ignored</param>
        /// <seealso cref="ITimemarkProvider.GetTimemark(X509Certificate2, DateTime, byte[])"/>
        /// <returns>The fixed time</returns>
        public DateTime GetTimemark(X509Certificate2 sender, DateTime signingTime, byte[] signatureValue)
        {
            return Date;
        }
    }
}
