using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Helper
{
    public class LoggingEndpointBehavior : IEndpointBehavior
    {
        private readonly ILogger<LoggingMessageInspector> _logger;

        public LoggingEndpointBehavior(ILogger<LoggingMessageInspector> logger)
        {
            _logger = logger;
        }

        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters) { }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
            clientRuntime.ClientMessageInspectors.Add(new LoggingMessageInspector(_logger));
        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher) { }

        public void Validate(ServiceEndpoint endpoint) { }
    }
}
