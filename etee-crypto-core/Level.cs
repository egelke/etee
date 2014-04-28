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
using System.Text;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>
    /// Security levels based to the "CAdES Baseline Profile" levels.
    /// </summary>
    [Flags]
    public enum Level : int
    {

        /// <summary>
        /// Baseline level:
        /// <para>
        /// No time based on current time, no time-stamp or time-mark is required (but time-stamps are processed if encountered).
        /// </para>
        /// <para>
        /// No revocation information is embedded, revocation is verified via embedded and/or on-line information (but the embedded info will be quickly outdated).
        /// </para>
        /// </summary>
        B_Level = 0x000,

        /// <summary>
        /// Time stamped/marked level:
        /// <para>
        /// Same as <see cref="B_Level"/> with time validation, requires a time-stamp or time-mark from a time-mark authority (e.g. ehBox, Recip-e... or intenal).
        /// </para>
        /// </summary>
        T_Level = 0x001,

        /// <summary>
        /// For internal use only.
        /// </summary>
        L_Level = 0x010,

        /// <summary>
        /// For internal use only.
        /// </summary>
        A_level = 0x100,

        /// <summary>
        /// Long lived time stamped/marked level:
        /// <para>
        /// Same as <see cref="T_Level"/> where revocation information is embedded during sealing, unsealing will still resolve on-line information if needed.
        /// </para>
        /// <para>
        /// <strong>Warning:</strong> use only with stores that aren't time-marks but which your trust anyway.  You always need to use <see cref="LTA_Level"/>
        /// in case of arbitration.
        /// </para>
        /// </summary>
        LT_Level = L_Level | T_Level,

        /// <summary>
        /// Long lived archivable time stamped/marked level.
        /// <para>
        /// Same as <see cref="LT_Level"/> for sealing, unsealing will check the time-stamp chain is still valid at the time of validation (not applicable with time-marks).
        /// </para>
        /// <para>
        /// The library does not support adding or verifying a archive time-stamp, but does already indicate when it is required <see cref="Egelke.EHealth.Etee.Crypto.Status.SignatureSecurityInformation.TimestampRenewalTime"/>
        /// </para>
        /// </summary>
        LTA_Level = LT_Level | A_level
    }
}
