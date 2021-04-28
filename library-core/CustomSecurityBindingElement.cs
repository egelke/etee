using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;

namespace Egelke.Wcf.Client
{
    public class CustomSecurityBindingElement : BindingElement
    {
        public override BindingElement Clone()
        {
            return new CustomSecurityBindingElement();
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
            /*
            SecurityCredentialsManager credentialsManager = context.BindingParameters.Find<SecurityCredentialsManager>();
            if (credentialsManager == null)
            {
                credentialsManager = ClientCredentials.CreateDefaultCredentials();
            }
            */

            return new CustomSecurityChannelFactory<TChannel>(context.BuildInnerChannelFactory<TChannel>()); ;
        }
    }
}
