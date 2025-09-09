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

using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Net.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom WCF binding for eHealth.
    /// </summary>
    /// <seealso href="https://github.com/dotnet/wcf/blob/main/src/System.Private.ServiceModel/src/System/ServiceModel/Channels/TransportSecurityBindingElement.cs">Inspired on</seealso>
    public class CustomSecurityBindingElement : BindingElement
    {
        private readonly ILogger _logger;

        private CustomSecurity _security;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="security">configuration to apply</param>
        /// <param name="logger">optional logger</param>
        public CustomSecurityBindingElement(CustomSecurity security, ILogger<CustomSecurity> logger = null)
        {
            MessageSecurityVersion = security.SecurityVersion;
            SignParts = SignParts.Timestamp;

            _security = security;
            _logger = logger ?? TraceLogger.CreateTraceLogger<CustomSecurity>();
        }

        /// <summary>
        /// Copy constructor.
        /// </summary>
        /// <param name="that">instance to copy from</param>
        public CustomSecurityBindingElement(CustomSecurityBindingElement that)
        {
            this.MessageSecurityVersion = that.MessageSecurityVersion;
            this.SignParts = that.SignParts;

            this._security = that._security;
            this._logger = that._logger;
        }

        /// <summary>
        /// WS-Security version to use.
        /// </summary>
        public SecurityVersion MessageSecurityVersion { get; set; }

        /// <summary>
        /// Parts to sign.
        /// </summary>
        public SignParts SignParts { get; set; }

        /// <summary>
        /// Clone the instance
        /// </summary>
        /// <returns>clone of the instance</returns>
        public override BindingElement Clone()
        {
            return new CustomSecurityBindingElement(this);
        }

        /// <summary>
        /// Gets proper from the context for this instance.
        /// </summary>
        /// <typeparam name="T">type of property to obtain</typeparam>
        /// <param name="context">context to look for the property</param>
        /// <returns>the propery from the context</returns>
        public override T GetProperty<T>(BindingContext context)
        {
            return context.GetInnerProperty<T>();
        }

        /// <summary>
        /// Check if a channel factory can be created.
        /// </summary>
        /// <typeparam name="TChannel">type of channel the factory need to be able to create</typeparam>
        /// <param name="context">context with parameters</param>
        /// <returns>always true</returns>
        public override bool CanBuildChannelFactory<TChannel>(BindingContext context)
        {
            return true;
        }

        /// <summary>
        /// Create a channel factory, replacing the client credentials with custom credentails if needed.
        /// </summary>
        /// <typeparam name="TChannel">type of channel the factory need to be able to create</typeparam>
        /// <param name="context">context with parameters</param>
        /// <returns>new instance of custom channel factory</returns>
        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            ClientCredentials clientCredentials = context.BindingParameters.Find<ClientCredentials>();
            if (!(clientCredentials is CustomClientCredentials))
            {
                clientCredentials = new CustomClientCredentials(clientCredentials);
                context.BindingParameters.Remove(typeof(ClientCredentials));
                context.BindingParameters.Add(clientCredentials);
            }
            return new CustomSecurityChannelFactory<TChannel>(_logger, context.BuildInnerChannelFactory<TChannel>())
            {
                ClientCredentials = clientCredentials,
                MessageSecurityVersion = this.MessageSecurityVersion,
                SignParts = this.SignParts,
                Security = this._security
            };
        }
    }
}
