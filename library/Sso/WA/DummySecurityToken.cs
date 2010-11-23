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
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IdentityModel.Tokens;
using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace Siemens.EHealth.Client.Sso.WA
{
    internal class DummySecurityToken : SecurityToken
    {

        public override bool CanCreateKeyIdentifierClause<T>()
        {
            if (typeof(T) == typeof(X509IssuerSerialKeyIdentifierClause))
            {
                return true;
            }
            return base.CanCreateKeyIdentifierClause<T>();
        }

        public override T CreateKeyIdentifierClause<T>()
        {
            if (typeof(T) == typeof(X509IssuerSerialKeyIdentifierClause))
            {
                return (new X509IssuerSerialKeyIdentifierClause("dummy", "1") as T);
            }
            return base.CreateKeyIdentifierClause<T>();
        }


        public override string Id
        {
            get { throw new NotImplementedException(); }
        }

        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get {
                List<SecurityKey> list = new List<SecurityKey>();
                list.Add(new RsaSecurityKey(RSA.Create()));
                return new ReadOnlyCollection<SecurityKey>(list);
            }
        }

        public override DateTime ValidFrom
        {
            get { throw new NotImplementedException(); }
        }

        public override DateTime ValidTo
        {
            get { throw new NotImplementedException(); }
        }
    }
}
