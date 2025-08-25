using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using System.Text;

namespace Egelke.EHealth.Client.Security
{
    //TODO::See https://docs.microsoft.com/en-us/dotnet/api/system.servicemodel.description.clientcredentials

    public class WsTrustClientCredentials : ClientCredentials
    {
        public ClientCredentials ClientCredentials { get; private set; }

        internal SecurityTokenManager SecurityTokenManager { get; private set; }

        public WsTrustClientCredentials() : base() { }

        public WsTrustClientCredentials(ClientCredentials clientCredentials)
        {
            ClientCredentials = clientCredentials;
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new WsTrustClientTokenManager(this);
        }
    }
}
