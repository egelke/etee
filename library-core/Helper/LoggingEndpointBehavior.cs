/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Helper
{
    /// <summary>
    /// To enable message logging on an endpoint.
    /// </summary>
    /// <remarks>
    /// This logger does not log the signature since they are added while the message is sent.
    /// </remarks>
    public class LoggingEndpointBehavior : IEndpointBehavior
    {
        private readonly ILogger<LoggingMessageInspector> _logger;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="logger">The logger to log the messages too</param>
        public LoggingEndpointBehavior(ILogger<LoggingMessageInspector> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Apply the binding parameters, this is a no-op.
        /// </summary>
        /// <param name="endpoint">the relevant endpoint</param>
        /// <param name="bindingParameters">the binding parameters to apply</param>
        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters) {
            //noop
        }

        /// <summary>
        /// Apply the client behaviour, attached the logging message inspector.
        /// </summary>
        /// <param name="endpoint">The relevant endpoint, not used</param>
        /// <param name="clientRuntime">The client runtime, not used</param>
        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
            clientRuntime.ClientMessageInspectors.Add(new LoggingMessageInspector(_logger));
        }

        /// <summary>
        /// Apply the bispatch behaviour, this is a no-op.
        /// </summary>
        /// <param name="endpoint">the relevant endpoint</param>
        /// <param name="endpointDispatcher">the dispatcher</param>
        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher) {
            //noop
        }

        /// <summary>
        /// Validates that an enpoint meets the criteria.
        /// This is a no-op, all endoints do.
        /// </summary>
        /// <param name="endpoint">The relevant endpoint</param>
        public void Validate(ServiceEndpoint endpoint) {
            //noop
        }
    }
}
