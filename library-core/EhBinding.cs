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
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using Egelke.EHealth.Client.Security;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client
{
    /// <summary>
    /// WCF Binding for eHealth, supports both X509 and SAML-HOK via WS-Trust.
    /// </summary>
    public class EhBinding : Binding
    {
        /// <summary>
        /// Optional logger.
        /// </summary>
        public ILogger<CustomSecurity> Logger { get; }

        /// <summary>
        /// Security configuration, defaults to X509 auth.
        /// </summary>
        public CustomSecurity Security { get; } = new CustomSecurity();

        /// <summary>
        /// Specifies if proxy config should be used for locahost or not.
        /// </summary>
        /// <value>
        /// Set to true to bypass proxy for localhost (default).
        /// </value>
        public bool BypassProxyOnLocal { get; set; } = true;

        /// <summary>
        /// Use the system/OS proxy config or not, by default it does use it.
        /// </summary>
        public bool UseDefaultWebProxy { get; set; } = true;

        /// <summary>
        /// The address of the proxy to use for this binding.
        /// </summary>
        public Uri ProxyAddress { get; set; }

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="logger">Optional logger</param>
        public EhBinding(ILogger<CustomSecurity> logger = null)
        {
            Logger = logger;
        }

        /// <summary>
        /// Create the binding elements.
        /// </summary>
        /// <returns>Collection of: security, message encoding and transport</returns>
        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection() {
                CreateSecurity(),
                CreateMessageEncoding(),
                CreateTransport()
            };
            return elements;
        }

        /// <summary>
        /// Create eHealth specific security element.
        /// </summary>
        /// <returns>Custom security element</returns>
        protected BindingElement CreateSecurity()
        {
            return new CustomSecurityBindingElement(Security, Logger)
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity11,
                SignParts = SignParts.All
            };
        }

        /// <summary>
        /// Create soap11 message encoding element
        /// </summary>
        /// <returns>standard message encoding element</returns>
        protected MessageEncodingBindingElement CreateMessageEncoding()
        {
            return new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.Soap11,
                
            };
        }

        /// <summary>
        /// Create https transport with proxy configuration element
        /// </summary>
        /// <returns>standard https transport element</returns>
        protected TransportBindingElement CreateTransport()
        {
            return new HttpsTransportBindingElement()
            {
                AuthenticationScheme = System.Net.AuthenticationSchemes.Anonymous,
                BypassProxyOnLocal = BypassProxyOnLocal,
                UseDefaultWebProxy = UseDefaultWebProxy,
                ProxyAddress = ProxyAddress
            };
        }

        /// <summary>
        /// The expected scheme (https).
        /// </summary>
        public override string Scheme => "https";
    }
}
