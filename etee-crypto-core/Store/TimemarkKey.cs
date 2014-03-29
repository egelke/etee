/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Store
{
    /// <summary>
    /// The key to retrieve a time-mark by.
    /// </summary>
    public class TimemarkKey
    {
        /// <summary>
        /// The signer of the message.
        /// </summary>
        /// <remarks>
        /// The entire certificate is provided so the time-mark authority can
        /// decide itself how to identify the signer, e.g. thumpprint, 
        /// serial+issuer, ...
        /// </remarks>
        public X509Certificate2 Signer { get; set; }

        /// <summary>
        /// The signing time indicated by the message.
        /// </summary>
        public DateTime SigningTime { get; set; }

        /// <summary>
        /// The signature value of the message, to uniquely link it to the message.
        /// </summary>
        public byte[] SignatureValue { get; set; }
    }
}
