using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.ServiceModel.Description;
using System.Text;
using Egelke.EHealth.Client.Security;


namespace Egelke.EHealth.Client
{
    public class EhCredentials : ClientCredentials
    {
        public EhCredentials() : base() { }

        public EhCredentials(ClientCredentials other) : base(other)
        {
            //this.Session = other.Session;
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new CustomSecurityTokenManager(this);
        }


        protected override ClientCredentials CloneCore()
        {
            return new EhCredentials(this);
        }
    }
}
