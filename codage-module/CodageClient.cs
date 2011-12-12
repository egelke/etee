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
using System.ServiceModel;
using System.Net.Security;
using System.ServiceModel.Channels;
using System.Runtime.Serialization;
using System.Xml.Serialization;
using Siemens.EHealth.Client.Sso.WA;

namespace Siemens.EHealth.Client.Codage
{
    [ServiceContractAttribute(ProtectionLevel = ProtectionLevel.Sign, Namespace = "http://www.ehealth.be/webservices/cod", ConfigurationName = "CodageV1", Name="CodagePort")]
    public interface CodagePort
    {
        [OperationContractAttribute(Action = "*", ReplyAction = "*")]
        Message Request(Message request);
    }

    public class CodageClient : ClientBase<CodagePort>
    {
        public CodageClient()
        {
        }

        public CodageClient(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        public CodageClient(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public CodageClient(string endpointConfigurationName, EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public CodageClient(Binding binding, EndpointAddress remoteAddress) :
            base(binding, remoteAddress)
        {
        }

        public EncodeResponseType Encode(EncodeRequestType request)
        {
            Message requestMsg = Message.CreateMessage(MessageVersion.Soap11, "http://www.ehealth.be/webservices/cod/encode", request, new XmlSerializerObjectSerializer(typeof(EncodeRequestType)));
            Message responseMsg = base.Channel.Request(requestMsg);
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 1024));
            }
            return responseMsg.GetBody<EncodeResponseType>(new XmlSerializerObjectSerializer(typeof(EncodeResponseType)));
        }
        
        public DecodeResponseType Decode(DecodeRequestType request)
        {
            Message requestMsg = Message.CreateMessage(MessageVersion.Soap11, "http://www.ehealth.be/webservices/cod/decode", request, new XmlSerializerObjectSerializer(typeof(DecodeRequestType)));
            Message responseMsg = base.Channel.Request(requestMsg);
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 1024));
            }
            return responseMsg.GetBody<DecodeResponseType>(new XmlSerializerObjectSerializer(typeof(DecodeResponseType)));
        }
    }
}
