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
    /// Contract of a Timemark provider
    /// </summary>
    /// <remarks>
    /// Timemark provider keep a consultable ledger off all time marks.
    /// </remarks>
    public interface ITimemarkProvider
    {
        /// <summary>
        /// Request the to add a timemark to the ledger for an e-signature.
        /// </summary>
        /// <param name="sender">The subject in the form of a certificate, normally the signer</param>
        /// <param name="signingTime">The time the signature was placed</param>
        /// <param name="signatureValue">The binary value of the signature</param>
        /// <returns>The timemark recorded by the provider</returns>
        DateTime GetTimemark(X509Certificate2 sender, DateTime signingTime, byte[] signatureValue);
    }
}
