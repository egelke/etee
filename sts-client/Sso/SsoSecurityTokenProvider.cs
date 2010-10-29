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
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Security;
using System.IO;
using System.Xml;
using System.Globalization;
using System.ServiceModel.Security.Tokens;
using Siemens.EHealth.Client.Sso.Sts.Service;
using Siemens.EHealth.Client.Sso;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Description;
using System.Net;
using System.Reflection;
using System.Collections.ObjectModel;

namespace Siemens.EHealth.Client.Sso
{
    public class SsoSecurityTokenProvider : SecurityTokenProvider
    {
        private static readonly MethodInfo servicePointMethod = typeof(ServicePoint).GetMethod("UpdateServerCertificate", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(X509Certificate) }, null);

        private IssuedSecurityTokenParameters tokenRequirement;
        private SsoClientCredentials clientCredentials;

        public SsoSecurityTokenProvider(SsoClientCredentials clientCredentials, IssuedSecurityTokenParameters tokenRequirement)
        {
            this.clientCredentials = clientCredentials;
            this.tokenRequirement = tokenRequirement;
        }

        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            Collection<XmlElement> reqParams = new Collection<XmlElement>();
            foreach (XmlElement param in tokenRequirement.AdditionalRequestParameters)
            {
                if (param.NamespaceURI == "urn:oasis:names:tc:SAML:1.0:assertion")
                {
                    reqParams.Add(param);
                }
            }


            //Get a new assertion token for the session
            StsClient target = new StsClient(tokenRequirement.IssuerBinding, tokenRequirement.IssuerAddress);
            target.ClientCredentials.ClientCertificate.Certificate = clientCredentials.ClientCertificate.Certificate;
            target.InnerChannel.OperationTimeout = timeout;

            //TODO::Remove after fix MS (Bug of cashed certificates when behind proxy)
            ServicePoint targetSp = ServicePointManager.FindServicePoint(target.Endpoint.Address.Uri, HttpWebRequest.DefaultWebProxy);
            if (targetSp != null)
            {
                servicePointMethod.Invoke(targetSp, new Object[] { null });
            }

            XmlElement assertion = target.RequestTicket("Anonymous", clientCredentials.Session, clientCredentials.Duration, reqParams, tokenRequirement.ClaimTypeRequirements);
            

            //TODO::Remove after fix MS (Bug of cashed certificates when behind proxy)
            targetSp = ServicePointManager.FindServicePoint(target.Endpoint.Address.Uri, HttpWebRequest.DefaultWebProxy);
            if (targetSp != null)
            {
                servicePointMethod.Invoke(targetSp, new Object[] { null });
            }

            XmlNamespaceManager nsmngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
            nsmngr.AddNamespace("saml", "urn:oasis:names:tc:SAML:1.0:assertion");

            //Get some date from the assertion token
            DateTime notBefore = DateTime.Parse(assertion.SelectSingleNode("saml:Conditions/@NotBefore", nsmngr).Value, null, DateTimeStyles.RoundtripKind);
            DateTime notOnOrAfter = DateTime.Parse(assertion.SelectSingleNode("saml:Conditions/@NotOnOrAfter", nsmngr).Value, null, DateTimeStyles.RoundtripKind);
            String assertionId = assertion.SelectSingleNode("@AssertionID", nsmngr).Value;

            // Create a KeyIdentifierClause for the SamlSecurityToken
            SamlAssertionKeyIdentifierClause samlKeyIdentifierClause = new SamlAssertionKeyIdentifierClause(assertionId);

            return new GenericXmlSecurityToken(assertion, new X509SecurityToken(clientCredentials.Session), notBefore, notOnOrAfter, samlKeyIdentifierClause, samlKeyIdentifierClause, null);
        }
    }
}
