using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using Egelke.EHealth.Client.Security;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Sts
{
    public class SsoBinding : EhBinding
    {
        public SsoBinding(ILogger<CustomSecurity> logger = null) : base(logger) { }

        protected override BindingElement CreateSecurity()
        {
            return new CustomSecurityBindingElement(logger: Logger)
            {
                MessageSecurityVersion = SecurityVersion.WSSecurity10,
                SignParts = SignParts.All
            };
        }

    }
}
