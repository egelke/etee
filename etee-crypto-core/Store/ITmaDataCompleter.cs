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
    /// Message verifier for time-mark authorities.
    /// </summary>
    public interface ITmaDataCompleter
    {
        /// <summary>
        /// Completes the provided message and returns the time-mark key.
        /// </summary>
        /// <remarks>
        /// Has an output parameter that will provide the time-mark key.  As a time-mark authority
        /// you are supposed use this key for the audit trail used for time-marking.  It must also
        /// be possibel to lookup the time-mark of the message via this key.
        /// </remarks>
        /// <seealso cref="IDataCompleter.Complete(Stream)"/>
        /// <param name="sealedData">The sealed message to which the information must be added</param>
        /// <param name="timemarkKey">The time-mark key to be linked to the message</param>
        /// <exception cref="InvalidMessageException">When the provided message isn't valid</exception>
        /// <returns>The sealed message to which the information is added</returns>
        Stream Complete(Stream sealedData, out TimemarkKey timemarkKey);
    }
}
