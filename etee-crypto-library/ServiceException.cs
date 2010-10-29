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

namespace Siemens.EHealth.Etee.Crypto.Library
{
    public class ServiceException : Exception
    {
        internal static void Check(ServiceClient.GetEtkResponse response)
        {
            Exception inner = null;
            foreach (Object item in response.Items)
            {
                if (item is ServiceClient.ErrorType1)
                {
                    inner = new ServiceException((ServiceClient.ErrorType1)item, inner);
                }
            }
            if (response.Status.Code != "200") throw new ServiceException(response, inner);
            if (inner != null) throw inner;
        }


        internal static void Check(ServiceClient.EteeResponseType response)
        {
            Exception inner = null;
            if (response.Error != null)
            {
                foreach (ServiceClient.ErrorType error in response.Error)
                {
                    inner = new ServiceException(error, inner);
                }
            }
            if (response.Status.Code != "200") throw new ServiceException(response.Status, inner);
            if (inner != null) throw inner;
        }

        private String code;

        public String Code
        {
            get { return code; }
            set { code = value; }
        }

        
       
        internal ServiceException(ServiceClient.EteeResponseTypeStatus error)
            : base(error.Message)
        {
            this.code = error.Code;
        }

        internal ServiceException(ServiceClient.EteeResponseTypeStatus error, Exception inner)
            : base(error.Message, inner)
        {
            this.code = error.Code;
        }

        internal ServiceException(ServiceClient.ErrorType1 error)
            : base(error.Message)
        {
            this.code = error.Code;
        }

        internal ServiceException(ServiceClient.ErrorType1 error, Exception inner)
            : base(error.Message, inner)
        {
            this.code = error.Code;
        }

        private ServiceException(ServiceClient.ResponseType response)
            : base((from m in response.Status.Message where m.Lang == ServiceClient.LangageType.EN select m.Value).Single())
        {
            this.code = response.Status.Code;
        }

        private ServiceException(ServiceClient.ResponseType response, Exception inner)
            : base((from m in response.Status.Message where m.Lang == ServiceClient.LangageType.EN select m.Value).Single(), inner)
        {
            this.code = response.Status.Code;
        }

        private ServiceException(ServiceClient.ErrorType error)
            : base((from m in error.Message where m.Lang == ServiceClient.LangageType.EN select m.Value).Single())
        {
            this.code = error.Code;
        }

        private ServiceException(ServiceClient.ErrorType error, Exception inner)
            : base((from m in error.Message where m.Lang == ServiceClient.LangageType.EN select m.Value).Single(), inner)
        {
            this.code = error.Code;
        }

    }
}
