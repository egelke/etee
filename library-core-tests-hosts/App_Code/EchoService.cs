using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Web;

namespace Egelke.Wcf.Client.Test.Host
{
    [ServiceContract(Namespace = "urn:test", Name = "EchoPort")]
    public interface IEchoService
    {
        [OperationContract(Action = "urn:test:echo:ping", ReplyAction = "urn:test:echo:pong")]
        [return: MessageParameter(Name = "pong")]
        string Echo(string ping);
    }

    public class EchoService : IEchoService
    {
        public string Echo(string ping)
        {
            return ping;
        }
    }
}