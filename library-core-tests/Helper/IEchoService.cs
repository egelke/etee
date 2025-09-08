using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.Text;

namespace library_core_tests
{
    [ServiceContract(Namespace = "urn:test", Name = "EchoPort")]
    interface IEchoService
    {
        [OperationContract(Action = "urn:test:echo:ping", ReplyAction = "*")]
        [return: MessageParameter(Name = "pong")]
        string Echo(string ping);
    }
}
