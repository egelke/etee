/*
 * This file is part of .Net ETEE for eHealth.
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
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Decrypt;

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public class VerifyException<Violation> : Exception
        where Violation : struct, IConvertible
    {
        private SecurityResult<Violation> result;

        public SecurityResult<Violation> Result
        {
            get { return result; }
            set { result = value; }
        }

        public VerifyException(SecurityResult<Violation> result)
            : base()
        {
            this.result = result;
        }

        public VerifyException(String message, SecurityResult<Violation> result)
            : base(message)
        {
            this.result = result;
        }

        

        public override string Message
        {
            get
            {
                if (String.IsNullOrWhiteSpace(base.Message))
                {
                    return result.ToString();
                }
                else
                {
                    return base.Message + "':\n" + result.ToString();
                }
            }
        }


    }
}
