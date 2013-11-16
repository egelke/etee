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
using System.ServiceModel.Description;
using System.IdentityModel.Selectors;

namespace Egelke.EHealth.Client.Sso.WA
{
    public class OptClientCredentials : ClientCredentials
    {
        public OptClientCredentials()
            : base()
        {

        }

        public OptClientCredentials(OptClientCredentials other)
            : base(other)
        {

        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new OptSecurityTokenManager(this);
        }

        protected override ClientCredentials CloneCore()
        {
            return new OptClientCredentials(this);
        }

    }
}
