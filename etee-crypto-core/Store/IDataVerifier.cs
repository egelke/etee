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

using Egelke.EHealth.Etee.Crypto.Status;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Store
{
    /// <summary>
    /// Message verifier for non time-mark authority.
    /// </summary>
    public interface IDataVerifier
    {
        /// <summary>
        /// Verifies the provided message.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Verifies the authentication part of the message, it does not decrypt the message
        /// or verifies the signature (non-repudiation) part.  It does not require the 
        /// possession of any decryption key and keeps the confidiality of the content.
        /// </para>
        /// <para>
        /// The level of verification depends on the level specified during creation. When required
        /// by the level, the siging time is validated via the embedded time-stamp or the time-mark provided
        /// that is specified during creation.
        /// </para>
        /// </remarks>
        /// <param name="sealedData">The message to verify</param>
        /// <returns>The result and additional information about the authentication part of the message</returns>
        SignatureSecurityInformation Verify(Stream sealedData);
    }
}
