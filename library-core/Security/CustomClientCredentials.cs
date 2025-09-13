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
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using System.Text;


namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom client credentails for WCF that support eHealth.
    /// </summary>
    public class CustomClientCredentials : ClientCredentials
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public CustomClientCredentials() : base() { }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="other">instance to copy from</param>
        public CustomClientCredentials(ClientCredentials other) : base(other)
        {

        }

        /// <summary>
        /// Create the token manager for the credentails.
        /// </summary>
        /// <returns>An custom token manager for eHealth</returns>
        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new CustomSecurityTokenManager(this);
        }

        /// <summary>
        /// Clones the instance using the copy constructor.
        /// </summary>
        /// <returns>Clone of the instance</returns>
        protected override ClientCredentials CloneCore()
        {
            return new CustomClientCredentials(this);
        }
    }
}
