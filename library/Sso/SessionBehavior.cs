/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Description;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;

namespace Siemens.EHealth.Client.Sso
{
    public class SessionBehavior : IEndpointBehavior
    {

        private X509Certificate2 session;

        private TimeSpan duration;

        public SessionBehavior(X509Certificate2 session, TimeSpan duration)
        {
            this.session = session;
            this.duration = duration;
        }

        #region IEndpointBehavior Members

        public void AddBindingParameters(ServiceEndpoint endpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
            SsoClientCredentials cred = bindingParameters.Find<SsoClientCredentials>();
            if (cred == null) throw new ConfigurationErrorsException("The session behavior must be used in conjunction with SoClientCredentials");
            cred.Session = session;
            cred.Duration = duration;
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.ClientRuntime clientRuntime)
        {

        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.EndpointDispatcher endpointDispatcher)
        {

        }

        public void Validate(ServiceEndpoint endpoint)
        {
        }

        #endregion
    }
}
