using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Net.Security;
using Siemens.EHealth.Client.RnTest.PhoneticSearch;
using Siemens.EHealth.Client.Sso.WA;

namespace Siemens.EHealth.Client.RnTest.Service_References.phoneticSearch
{
    [ServiceContractAttribute(ProtectionLevel = ProtectionLevel.Sign, Namespace = "http://ehealth.fgov.be/consultRN/phoneticSearch/v1_0/", ConfigurationName = "PhoneticSearchV1", Name = "PhoneticSearchPort")]
    public interface PhoneticSearchPort
    {
        [OperationContractAttribute(Action = "*", ReplyAction = "*")]
        Message Request(Message request);
    }

    public class PhoneticSearhClient : ClientBase<PhoneticSearchPort>
    {
        public PhoneticSearhClient()
        {
        }

        public PhoneticSearhClient(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        public PhoneticSearhClient(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public PhoneticSearhClient(string endpointConfigurationName, EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        public PhoneticSearhClient(Binding binding, EndpointAddress remoteAddress) :
            base(binding, remoteAddress)
        {
        }

        public SearchPhoneticReply Search(SearchPhoneticRequest request)
        {
            Message requestMsg = Message.CreateMessage(MessageVersion.Soap11, "http://ehealth.fgov.be/consultRN/identifyPerson/phoneticSearch/search", request, new XmlSerializerObjectSerializer(typeof(SearchPhoneticRequest)));
            Message responseMsg = base.Channel.Request(requestMsg);
            if (responseMsg.IsFault)
            {
                throw new FaultException(MessageFault.CreateFault(responseMsg, 1024));
            }
            return responseMsg.GetBody<SearchPhoneticReply>(new XmlSerializerObjectSerializer(typeof(SearchPhoneticReply)));
        }
    }
}
