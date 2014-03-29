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
    /// Message completer non time-mark authority.
    /// </summary>
    public interface IDataCompleter
    {
        /// <summary>
        /// Completes the provided message.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Completes the authentication part of the message, it does not decrypt the message
        /// or changes the signature (non-repudiation) part.  It does not require the 
        /// possession of any decryption key and keeps the confidiality of the content.
        /// </para>
        /// <para>
        /// The level of the returned messages depends on the level specified during creation. When required
        /// by the level, a time-stamp is added via the provided time-stamp authority.  In case of a 
        /// time-mark authority, not time information is added.
        /// </para>
        /// <para>
        /// The returned <c>Stream</c> is either a memory stream or a stream to a temporally file that is
        /// deleted when the stream is closed.  Which depends on the <see cref="Egelke.EHealth.Etee.Crypto.Configuration.Settings.InMemorySize"/> setting.
        /// </para>
        /// </remarks>
        /// <param name="sealedData">The sealed message to which the information must be added</param>
        /// <exception cref="InvalidMessageException">When the provided message isn't valid</exception>
        /// <returns>The sealed message to which the information is added</returns>
        Stream Complete(Stream sealedData);
    }
}
