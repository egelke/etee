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

namespace Egelke.Wcf.Client.Security
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso href="https://github.com/dotnet/wcf/blob/main/src/System.Private.ServiceModel/src/System/ServiceModel/Channels/TransportSecurityBindingElement.cs">Inspired on</seealso>
    public class CustomSecurityBindingElement : BindingElement
    {
        private readonly ILogger _logger;



        public CustomSecurityBindingElement(ILogger<CustomSecurity> logger = null)
        {
            MessageSecurityVersion = SecurityVersion.WSSecurity11 ;
            SignParts = SignParts.Timestamp;
            _logger = logger ?? TraceLogger.CreateTraceLogger<CustomSecurity>();
        }

        public CustomSecurityBindingElement(CustomSecurityBindingElement that)
        {
            this.MessageSecurityVersion = that.MessageSecurityVersion;
            this.SignParts = that.SignParts;
            this._logger = that._logger;
        }

        public SecurityVersion MessageSecurityVersion { get; set; }

        public SignParts SignParts { get; set; }

        public override BindingElement Clone()
        {
            return new CustomSecurityBindingElement(this);
        }

        public override T GetProperty<T>(BindingContext context)
        {
            return context.GetInnerProperty<T>();
        }

        public override bool CanBuildChannelFactory<TChannel>(BindingContext context)
        {
            return true;
        }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            var clientCredentials = (ClientCredentials)context.BindingParameters[typeof(ClientCredentials)];
            return new CustomSecurityChannelFactory<TChannel>(_logger, context.BuildInnerChannelFactory<TChannel>())
            {
                ClientCredentials = clientCredentials,
                MessageSecurityVersion = this.MessageSecurityVersion,
                SignParts = this.SignParts
            };
        }
    }
}
