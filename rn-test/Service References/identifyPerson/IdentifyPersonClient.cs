using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Net.Security;
using Siemens.EHealth.Client.Sso.WA;
using Siemens.EHealth.Client.RnTest.IdentifyPerson;

namespace Siemens.EHealth.Client.RnTest.Service_References.phoneticSearch
{
    [ServiceContractAttribute(ProtectionLevel = ProtectionLevel.Sign, Namespace = "http://ehealth.fgov.be/consultRN/searchPersonBySSIN/v1_0/", ConfigurationName = "IdentifyPersonV1", Name = "IdentifyPersonPort")]
    public interface IdentifyPersonPort
    {
        [OperationContractAttribute(Action = "*", ReplyAction = "*")]
        Message Request(Message request);
    }

    public class IdentifyPersonClient : ClientBase<IdentifyPersonPort>
    {
        public IdentifyPersonClient()
        {
        }

        public IdentifyPersonClient(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        public IdentifyPersonClient(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public IdentifyPersonClient(string endpointConfigurationName, EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public IdentifyPersonClient(Binding binding, EndpointAddress remoteAddress) :
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
