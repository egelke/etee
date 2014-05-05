
using Egelke.EHealth.Client.Sso;
using Egelke.EHealth.Client.Sso.Sts;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Egelke.EHealth.Client.Builder
{
    public static class DoctorBuilder
    {
        public static Binding CreateBinding(String ssin, String nihii11, Uri stsUri)
        {
            var ssoBinding = new SsoBinding();
            ssoBinding.Security.Mode = WSFederationHttpSecurityMode.Message;
            ssoBinding.Security.Message.IssuedKeyType = SecurityKeyType.AsymmetricKey;
            ssoBinding.Security.Message.NegotiateServiceCredential = false;
            ssoBinding.Security.Message.EstablishSecurityContext = false;

            ssoBinding.Security.Message.IssuerAddress = new EndpointAddress(stsUri);
            ssoBinding.Security.Message.IssuerBinding = new StsBinding();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:person:ssin\"> " +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"+ssin+"</saml:AttributeValue> " +
                "</saml:Attribute>");
            ssoBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);
            doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin\"> " +
                  "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"+ssin+"</saml:AttributeValue> " +
                "</saml:Attribute>");
            ssoBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);

            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11"));

            return ssoBinding;
        }

        public static void ApplyBehaviors(this ClientBase<Object> client, X509Certificate2 session, String sessionStorePath, TimeSpan sessionDuration)
        {
            if (!Directory.Exists(sessionStorePath)) Directory.CreateDirectory(sessionStorePath);

            client.Endpoint.Behaviors.Remove<ClientCredentials>();
            client.Endpoint.Behaviors.Add(new SsoClientCredentials());
            XmlDocument fscConfig = new XmlDocument();
            fscConfig.LoadXml(@"<path>"+ sessionStorePath+ "</path>");
            client.Endpoint.Behaviors.Add(new SessionBehavior(session, sessionDuration, typeof(FileSessionCache), fscConfig));
        }

        public static CareProvider CreateCareProvider(String ssin, String nihii11)
        {
            var cp = new CareProvider();
            cp.Nihii = new Nihii();
            cp.Nihii.Quality = "doctor";
            cp.Nihii.Value = nihii11;
            cp.PhysicalPerson = new Id();
            cp.PhysicalPerson.Ssin = ssin;

            return cp;
        }
    }
}
