/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
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
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// WS-Security parts to sign, as flag.
    /// </summary>
    [Flags]
    public enum SignParts : int
    {
        /// <summary>
        /// Sign the Timestamp element in the WS-Security header.
        /// </summary>
        Timestamp           = 0x01,
        /// <summary>
        /// Sing the SOAP-Body element.
        /// </summary>
        Body                = 0x02,
        /// <summary>
        /// Sign the Binary Security Token elment in the WS-Security header.
        /// </summary>
        BinarySecurityToken = 0x04,
        /// <summary>
        /// Sgn Timestamp, Body and BinarySecurityToken
        /// </summary>
        All = Timestamp | Body | BinarySecurityToken
    }
}
