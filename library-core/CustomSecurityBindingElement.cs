using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Net.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;

namespace Egelke.Wcf.Client
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso href="https://github.com/dotnet/wcf/blob/main/src/System.Private.ServiceModel/src/System/ServiceModel/Channels/TransportSecurityBindingElement.cs">Inspired on</seealso>
    public class CustomSecurityBindingElement : BindingElement
    {


        public SecurityVersion MessageSecurityVersion
        {
            get; set;
        }

        public CustomSecurityBindingElement()
        {
            MessageSecurityVersion = SecurityVersion.WSSecurity11 ;
        }

        public CustomSecurityBindingElement(CustomSecurityBindingElement that)
        {
            this.MessageSecurityVersion = that.MessageSecurityVersion;
        }

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
            return new CustomSecurityChannelFactory<TChannel>(context.BuildInnerChannelFactory<TChannel>())
            {
                ClientCredentials = clientCredentials,
                MessageSecurityVersion = this.MessageSecurityVersion
            };
        }
    }
}
