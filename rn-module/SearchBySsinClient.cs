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
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Net.Security;
using Siemens.EHealth.Client.Sso.WA;

namespace Siemens.EHealth.Client.ConsultRn
{
    [ServiceContractAttribute(ProtectionLevel = ProtectionLevel.Sign, Namespace = "http://ehealth.fgov.be/consultRN/searchPersonBySSIN/v1_0/", ConfigurationName = "SearchBySsinV1", Name = "SearchBySsinPort")]
    public interface SearchBySsinPort
    {
        [OperationContractAttribute(Action = "*", ReplyAction = "*")]
        Message Request(Message request);
    }

    public class SearchBySsinClient : ClientBase<SearchBySsinPort>
    {
        public SearchBySsinClient()
        {
        }

        public SearchBySsinClient(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        public SearchBySsinClient(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public SearchBySsinClient(string endpointConfigurationName, EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public SearchBySsinClient(Binding binding, EndpointAddress remoteAddress) :
            base(binding, remoteAddress)
        {
        }

        public SearchBySSINReply Search(SearchBySSINRequest request)
        {
            Message requestMsg = Message.CreateMessage(MessageVersion.Soap11, "http://ehealth.fgov.be/consultRN/identifyPerson/searchPersonBySSIN/search", request, new XmlSerializerObjectSerializer(typeof(SearchBySSINRequest)));
            Message responseMsg = base.Channel.Request(requestMsg);
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 1024));
            }
            return responseMsg.GetBody<SearchBySSINReply>(new XmlSerializerObjectSerializer(typeof(SearchBySSINReply)));
        }
    }
}
