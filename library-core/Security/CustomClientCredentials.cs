using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using System.Text;


namespace Egelke.EHealth.Client.Security
{
    public class CustomClientCredentials : ClientCredentials
    {
        public CustomClientCredentials() : base() { }

        public CustomClientCredentials(ClientCredentials other) : base(other)
        {
            //this.Session = other.Session;
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new CustomSecurityTokenManager(this);
        }


        protected override ClientCredentials CloneCore()
        {
            return new CustomClientCredentials(this);
        }
    }
}
