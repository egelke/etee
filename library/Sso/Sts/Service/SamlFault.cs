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
using System.ServiceModel;
using System.Xml;

namespace Siemens.EHealth.Client.Sso.Sts.Service
{
    class SamlFault : CommunicationException
    {
        private StatusCode code;

        private XmlNodeList detail;

        public SamlFault(StatusCode code, String msg, XmlNodeList detail)
            : base(msg)
        {
            this.code = code;
            this.detail = detail;
        }

        public StatusCode Code
        {
            get
            {
                return code;
            }
        }

        public XmlNodeList Detail
        {
            get
            {
                return detail;
            }
        }

    }
}
