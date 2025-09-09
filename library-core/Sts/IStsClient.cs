/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *  Copyright (C) 2012 I.M. vzw
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
using System.IdentityModel.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Egelke.EHealth.Client.Sts
{
    /// <summary>
    /// Generice interface to obtain tokens, suitable for both SAML-P and WS-Trust implementations.
    /// </summary>
    public interface IStsClient
    {
        /// <summary>
        /// Obtain a new token from the sts.
        /// </summary>
        /// <param name="sessionCert">The session certificate, to be used as HOK for SAML</param>
        /// <param name="duration">The requested duration of the token</param>
        /// <param name="claims">List of claims to provide in the request</param>
        /// <returns>The token, in raw XML dom format, as returned by the sts</returns>
        XmlElement RequestTicket(X509Certificate2 sessionCert, TimeSpan duration, AuthClaimSet claims);
    }
}
