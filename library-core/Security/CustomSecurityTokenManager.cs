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
using System.ServiceModel;
using System.ServiceModel.Description;
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom WCF Token Manager for eHealth.
    /// </summary>
    public class CustomSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        /// <summary>
        /// Copy and conversion constructor.
        /// </summary>
        /// <param name="clientCredentials">instance to copy the properties from</param>
        public CustomSecurityTokenManager(ClientCredentials clientCredentials)
            : base(clientCredentials) { }

        /// <summary>
        /// Create a token provider.
        /// </summary>
        /// <param name="tokenRequirement">the requirements for the token provider</param>
        /// <returns>a new custom token provider</returns>
        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            return new CustomSecurityTokenProvider(tokenRequirement, ClientCredentials.ClientCertificate.Certificate);
        }
    }
}
