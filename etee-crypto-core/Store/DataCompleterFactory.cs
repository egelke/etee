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

using Egelke.EHealth.Client.Tsa;
using Egelke.EHealth.Etee.Crypto.Sender;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Store
{
    /// <summary>
    /// <see cref="IDataCompleter"/> factory class for sealed message stores.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Intended for sealed messages stores that will complete sealed messages but not nesesary seal them itself.
    /// Often these message store are time-mark authorities, but this isn't a required.
    /// </para>
    /// <para>
    /// Can't be used to complete B-Level since there is nothing to complete with that level.
    /// </para>
    /// </remarks>
    public static class DataCompleterFactory
    {

        /// <summary>
        /// Creates a completer to extend messages with validation data and time-stamp.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The resulting completer add a time-stamp via the time-stamp authority and optionally revocation information to the message.
        /// It is illegal to call this method with B-Level since this would not change the message in any way.
        /// </para>
        /// </remarks>
        /// <param name="level">The required level the complerer must produce: T-Level, LT-Level or LTA-Level</param>
        /// <param name="timestampProvider">The client of the time-stamp authority</param>
        /// <returns>The completer of the required level that will used the provided time-stamp authority client</returns>
        public static IDataCompleter Create(Level level, ITimestampProvider timestampProvider)
        {
            if (level == Level.B_Level) throw new NotSupportedException("Nothing to complete for B-level");
            if (timestampProvider == null) throw new ArgumentNullException("timestampProvider", "A timestamp provider is required with this method");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should be used for a level that requires time stamping");

            return new TripleWrapper(level, null, null, timestampProvider);
        }

        /// <summary>
        /// Creates a completer to extend messages that will be send to a time-mark authority with validation data
        /// </summary>
        /// <remarks>
        /// <para>
        /// The resulting completer add revocation information to the message.
        /// It is illegal to call this method with B-Level or T-Level since this would not change the message in any way.
        /// </para>
        /// </remarks>
        /// <param name="level">The required level the complerer must produce: LT-Level or LTA-Level</param>
        /// <returns>The completer of the required level to by a client of a time-mark authority</returns>
        public static IDataCompleter CreateForTimeMarkAuthority(Level level)
        {
            if (level == Level.B_Level || level == Level.T_Level) throw new NotSupportedException("Nothing to complete for B-level or T-Level for time-mark authority");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should be used for a level that requires time stamping");

            return new TripleWrapper(level, null, null, null);
        }

        /// <summary>
        /// Creates a completer to extend messages with validation data but not time-stamp.
        /// </summary>
        /// <remarks>
        /// The resulting completer does not add a time-stamp because it is either called by a time-marking authority itself or
        /// the message will be send to one.
        /// </remarks>
        /// <param name="level">The required level the complerer must produce: T-Level, LT-Level or LTA-Level</param>
        /// <returns>The completer of the required level to be used by a time-mark authority</returns>
        public static ITmaDataCompleter CreateAsTimeMarkAuthority(Level level)
        {
            if (level == Level.B_Level) throw new NotSupportedException("Nothing to complete for B-level");
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleWrapper(level, null, null, null);
        }

    }
}
