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
using System.Text;
using Egelke.EHealth.Etee.Crypto.Status;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public class VerifyException<Violation> : Exception
        where Violation : struct, IConvertible
    {

        public SecurityResult<Violation> Result { get; set; }

        public VerifyException(SecurityResult<Violation> result)
            : base()
        {
            this.Result = result;
        }

        public VerifyException(String message, SecurityResult<Violation> result)
            : base(message)
        {
            this.Result = result;
        }

        

        public override string Message
        {
            get
            {
                if (String.IsNullOrWhiteSpace(base.Message))
                {
                    return Result.ToString();
                }
                else
                {
                    return base.Message + "':\n" + Result.ToString();
                }
            }
        }


    }
}
