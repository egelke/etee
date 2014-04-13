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

using Egelke.EHealth.Client.Pki;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Store
{
    /// <summary>
    /// <see cref="IDataVerifier"/> factory class for sealed message stores.
    /// </summary>
    /// <remarks>
    /// Intended for sealed messages stores that will verify sealed messages but not necessary unseal them.
    /// Often these message store are time-mark authorities, but this isn't a required.
    /// </remarks>
    public class DataVerifierFactory
    {
        /// <summary>
        /// Creates an instance of the <see cref="IDataVerifier"/> interface to verify messages.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Verifies the authentication part of the message, not the signer (non-repudiation) of
        /// the message.  It does not decrypt the message, so the content remains hidden and it
        /// does not require the possession of any key.
        /// </para>
        /// <para>
        /// Can be used to verify all types of messages, including those with time information (T, LT and LTA-Level) in
        /// case a time-stamp authority is used and not a time-mark authority.
        /// </para>
        /// </remarks>
        /// <param name="level">The level to which a message must conform to, <c>null</c> meaning no revocation check must be done</param>
        /// <returns>The completer of the required level that will verify the message, using the embedded timestamps if needed</returns>
        public static IDataVerifier Create(Level? level)
        {
            return new TripleUnwrapper(level, null, new X509Certificate2Collection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="ITmaDataVerifier"/> interface to verify messages as time-mark authority.
        /// </summary>
        /// <remarks>
        /// For usage by a time mark authority, allows you to provide the known time-mark before the time-mark key is known.
        /// </remarks>
        /// <seealso cref="Create(Nullable{Level})"/>
        /// <param name="level">The level to which a message must conform to: T, LT or LTA level</param>
        /// <returns>The completer of the required level that will verify the message according to the provided date time</returns>
        public static ITmaDataVerifier CreateAsTimemarkAuthority(Level level)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleUnwrapper(level, null, new X509Certificate2Collection());
        }

        /// <summary>
        /// Creates an instance of the <see cref="ITmaDataVerifier"/> interface to verify messages retrieved from a time-mark authority.
        /// </summary>
        /// <remarks>
        /// For usage with messages that come from a time-mark authority (e.g. ehBox).  In case the message contains an embedded time-stamp,
        /// it takes precedence and the time mark authority isn't used.
        /// </remarks>
        /// <param name="level">The level to which a message must conform to: T, LT or LTA level</param>
        /// <param name="timemarkAuthority">The client of the time-mark authority used to retrieve the time-mark during verification</param>
        /// <returns>The completer of the required level that will verify the message with the provided time-mark authority</returns>
        public static IDataVerifier CreateFromTimemarkAuthority(Level level, ITimemarkProvider timemarkAuthority)
        {
            if ((level & Level.T_Level) != Level.T_Level) throw new ArgumentException("This method should for a level that requires time marking");

            return new TripleUnwrapper(level, timemarkAuthority, new X509Certificate2Collection());
        }
    }
}
