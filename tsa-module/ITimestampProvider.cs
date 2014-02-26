/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
 *  Copyright (C) 2012 I.M. vzw
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  Foobar is distributed in the hope that it will be useful,
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
using System.Text;

namespace Egelke.EHealth.Client.Tsa
{
    /// <summary>
    /// Interface a Timestamp Provider must implement
    /// </summary>
    /// <remarks>
    /// The library comes with an implementation for DSS and rfc3161 (TODO), but it is always possible to
    /// write your own implementation if required.
    /// </remarks>
    /// <seealso cref="DssTimestampProvider"/>
    public interface ITimestampProvider
    {
        /// <summary>
        /// Method called to request a timestamp.
        /// </summary>
        /// <remarks>
        /// <para>
        /// For implementers, this method should call the TSA to obtain a RFC3161 compliant timestamp token.
        /// </para>
        /// </remarks>
        /// <param name="hash">The hash of the document that must be timestamped</param>
        /// <param name="digestMethod">The hasm method that was used, in XML-DSIG (and related) format e.g. <literal>http://www.w3.org/2001/04/xmlenc#sha256</literal></param>
        /// <returns>Must return a binary version of a RFC3161 compliant timestamp token (not the response) valid for the provided hash</returns>
        byte[] GetTimestampFromDocumentHash(byte[] hash, String digestMethod);
    }
}
