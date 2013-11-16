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
using System.IdentityModel.Policy;
using System.IdentityModel.Claims;

namespace Egelke.EHealth.Client.Sso.WA
{
    internal class DummyAuthorizationPolicy : IAuthorizationPolicy
    {
        private ClaimSet issuance;

        public DummyAuthorizationPolicy(ClaimSet issuance)
        {
            this.issuance = issuance;
        }

        #region IAuthorizationPolicy Members

        public bool Evaluate(EvaluationContext evaluationContext, ref object state)
        {
            evaluationContext.AddClaimSet(this, issuance);
            evaluationContext.RecordExpirationTime(DateTime.UtcNow.AddDays(1.0));
            return true;
        }

        public System.IdentityModel.Claims.ClaimSet Issuer
        {
            get { return ClaimSet.System; }
        }

        #endregion

        #region IAuthorizationComponent Members

        public string Id
        {
            get { throw new NotImplementedException(); }
        }

        #endregion
    }
}
