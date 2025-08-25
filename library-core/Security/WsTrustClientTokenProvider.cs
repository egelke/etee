using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    public class WsTrustClientTokenProvider : SecurityTokenProvider
    {
        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            throw new NotImplementedException();
        }
    }
}
