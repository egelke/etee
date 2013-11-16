/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IdentityModel.Selectors;
using System.Collections.ObjectModel;
using System.IdentityModel.Policy;
using System.IdentityModel.Claims;

namespace Egelke.EHealth.Client.Sso.WA
{
    internal class DummySecurityTokenAuthenticator : SecurityTokenAuthenticator
    {
        private Uri uri;

        public DummySecurityTokenAuthenticator(Uri uri)
        {
            // TODO: Complete member initialization
            this.uri = uri;
        }
        protected override bool CanValidateTokenCore(System.IdentityModel.Tokens.SecurityToken token)
        {
            return token is DummySecurityToken;
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(System.IdentityModel.Tokens.SecurityToken token)
        {
            List<IAuthorizationPolicy> list = new List<IAuthorizationPolicy>();
            list.Add(new DummyAuthorizationPolicy(new DefaultClaimSet(Claim.CreateDnsClaim(uri.Host))));
            return new ReadOnlyCollection<IAuthorizationPolicy>(list);
        }
    }
}
