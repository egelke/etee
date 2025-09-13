using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.EtkDepot
{
    public class EtkDepotClient : ClientBase<EtkDepotPortType>
    {

        private readonly ILogger<EtkDepotClient> _logger;


        public EtkDepotClient(EndpointAddress remoteAddress, ILogger<EtkDepotClient> logger = null)
            : base(new EhBinding(), remoteAddress)
        {
            _logger = logger;
        }

        public EtkDepotClient(Binding binding, EndpointAddress remoteAddress, ILogger<EtkDepotClient> logger = null)
            : base(binding, remoteAddress)
        {
            _logger = logger;
        }

        public EncryptionToken[] GetEtk(params IdentifierType[] searchCriteria)
        {
            var req = new GetEtkRequest1()
            {
                GetEtkRequest = new GetEtkRequest()
                {
                    SearchCriteria = searchCriteria
                } 
            };

            var rsp = Channel.GetEtk(req)?.GetEtkResponse;

            if (rsp?.Status?.Code != "")
            {
                //rsp?.Status?.Message?.FirstOrDefault()
                throw new ServiceException(rsp?.Status?.Code);
            }
            return null;
        }
    }
}
