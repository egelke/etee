/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
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
using Siemens.EHealth.Client.Sso.WA;

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

            ISessionCache cache = (ISessionCache) Activator.CreateInstance(clientCredentials.Cache, clientCredentials.Config);

            //Check the cache for existing session.
            String id;
            List<String> idSort;
            id = clientCredentials.ClientCertificate.Certificate.Thumbprint + ";";
            id += clientCredentials.Session.Thumbprint + ";";
            idSort = new List<string>();
            foreach (XmlElement reqParam in reqParams)
            {
                String val;
                val = "{" + reqParam.GetAttribute("AttributeNamespace") + "}";
                val += reqParam.GetAttribute("AttributeName");
                val += "=";
                val += reqParam.GetElementsByTagName("AttributeValue", "urn:oasis:names:tc:SAML:1.0:assertion")[0].InnerText;
                val += ";";
                idSort.Add(val);
            }
            idSort.Sort();
            foreach (String val in idSort)
            {
                id += val;
            }
            idSort = new List<string>();
            foreach (ClaimTypeRequirement req in tokenRequirement.ClaimTypeRequirements)
            {
                String val = req.ClaimType + ";";
                idSort.Add(val);
            }
            idSort.Sort();
            foreach (String val in idSort)
            {
                id += val;
            }

            XmlNamespaceManager nsmngr = null;
            DateTime notOnOrAfter = DateTime.MinValue;            

            //Get the value from the cache
            XmlElement assertion = cache.Get(id);
            
            //If cache had a result, check if it is still valid
            if (assertion != null) 
            {
                nsmngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
                nsmngr.AddNamespace("saml", "urn:oasis:names:tc:SAML:1.0:assertion");

                notOnOrAfter = DateTime.Parse(assertion.SelectSingleNode("saml:Conditions/@NotOnOrAfter", nsmngr).Value, null, DateTimeStyles.RoundtripKind);

                if (notOnOrAfter < DateTime.UtcNow) 
                {
                    assertion = null;
                    cache.Remove(id);
                }
            }
            
            //If the cache wasn't successful, create new.
            if (assertion == null)
            {
                //Get a new assertion token for the session
                StsClient target = new StsClient(tokenRequirement.IssuerBinding, tokenRequirement.IssuerAddress);
                target.Endpoint.Behaviors.Remove<ClientCredentials>();
                target.Endpoint.Behaviors.Add(new OptClientCredentials());
                target.ClientCredentials.ClientCertificate.Certificate = clientCredentials.ClientCertificate.Certificate;
                target.InnerChannel.OperationTimeout = timeout;

                assertion = target.RequestTicket("Anonymous", clientCredentials.Session, clientCredentials.Duration, reqParams, tokenRequirement.ClaimTypeRequirements);

                nsmngr = new XmlNamespaceManager(assertion.OwnerDocument.NameTable);
                nsmngr.AddNamespace("saml", "urn:oasis:names:tc:SAML:1.0:assertion");

                notOnOrAfter = DateTime.Parse(assertion.SelectSingleNode("saml:Conditions/@NotOnOrAfter", nsmngr).Value, null, DateTimeStyles.RoundtripKind);

                cache.Add(id, assertion, notOnOrAfter);
            }

            //Get some date from the assertion token
            DateTime notBefore = DateTime.Parse(assertion.SelectSingleNode("saml:Conditions/@NotBefore", nsmngr).Value, null, DateTimeStyles.RoundtripKind);
            String assertionId = assertion.SelectSingleNode("@AssertionID", nsmngr).Value;

            // Create a KeyIdentifierClause for the SamlSecurityToken
            SamlAssertionKeyIdentifierClause samlKeyIdentifierClause = new SamlAssertionKeyIdentifierClause(assertionId);

            return new GenericXmlSecurityToken(assertion, new X509SecurityToken(clientCredentials.Session), notBefore, notOnOrAfter, samlKeyIdentifierClause, samlKeyIdentifierClause, null);
        }
    }
}
