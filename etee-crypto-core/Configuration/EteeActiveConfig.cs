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
using System.Text;
using System.Configuration;

namespace Egelke.EHealth.Etee.Crypto.Configuration
{
    internal static class EteeActiveConfig
    {

        private static SealActiveConfig seal;
        private static UnsealActiveConfig unseal;

        /// <summary>
        /// The max difference between the different clocks.
        /// </summary>
        static public TimeSpan ClockSkewness
        {
            get
            {
                return new TimeSpan(0, 5, 0);
            }
        }

        static public SealActiveConfig Seal
        {
            get
            {
                if (seal == null)
                {
                    seal = new SealActiveConfig();
                }
                return seal;
            }
        }

        static public UnsealActiveConfig Unseal
        {
            get
            {
                if (unseal == null)
                {
                    unseal = new UnsealActiveConfig();
                }
                return unseal;
            }
        }
    }
}
