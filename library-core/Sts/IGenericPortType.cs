using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Sts
{
    [ServiceContract]
    interface IGenericPortType
    {
        [OperationContract(Action = "*", ReplyAction = "*")]
        Message Send(Message request);

        [OperationContract(Action = "*", ReplyAction = "*")]
        Task<Message> SendAsync(Message request);

        [OperationContract(IsOneWay = true, Action = "*")]
        void SendOneWay(Message request);
    }
}
