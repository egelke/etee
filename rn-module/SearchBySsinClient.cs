using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Net.Security;
using Siemens.EHealth.Client.Sso.WA;

namespace Siemens.EHealth.Client.Rn.IdentifyPerson
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
