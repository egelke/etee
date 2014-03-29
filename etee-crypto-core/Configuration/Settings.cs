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

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    /// <summary>
    /// Global settings class of the library.
    /// </summary>
    public class Settings
    {
        private static Settings defaultInstance = new Settings();

        /// <summary>
        /// The default instance of the settings class, always use this.
        /// </summary>
        public static Settings Default
        {
            get
            {
                return defaultInstance;
            }
        }

        /// <summary>
        /// The max delay between the timestamp and signing time.
        /// </summary>
        /// <remarks>
        /// The default value is 5 minutes.
        /// </remarks>
        public TimeSpan TimestampGracePeriod { get; set; }

        /// <summary>
        /// The size of the message before the temp file directory is used instead of a memory stream.
        /// </summary>
        /// <value>
        /// <para>
        /// The default value is 1048576 or 1MB.
        /// </para>
        /// <para>
        /// This setting isn't used for messages generated with the eHealth 1.6 version of the library.
        /// </para>
        /// </value>
        public long InMemorySize { get; set; }

        /// <summary>
        /// Additional certificates that may be required but aren't in the windows certificate store.
        /// </summary>
        public X509Certificate2Collection ExtraStore { get; set; }

        private Settings() 
        {
            TimestampGracePeriod = new TimeSpan(0, 5, 0);
            InMemorySize = 1024 * 1024;
        }
    }
}
