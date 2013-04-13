using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Client.Sso;
using System.ServiceModel;
using System.IdentityModel.Tokens;
using Siemens.EHealth.Client.Sso.Sts;
using System.Xml;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;
using Egelke.EHealth.Client.ChapterIV;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;

namespace Egelke.EHealth.Client.ChapterIVTest
{
    [TestClass]
    public class ConsultExample
    {
        private static X509Certificate2 sign;
        private static X509Certificate2 auth;
        private static X509Certificate2 session;

        [ClassInitialize]
        public static void MyClassInitialize(TestContext testContext)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            //Select the care provider certificate issued by eHealth
            X509Certificate2 eh = store.Certificates.Find(X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2", false)[0];
            X509Certificate2 eid = store.Certificates.Find(X509FindType.FindByThumbprint, "c6c3cba1000c955c2e6289c6eb40bbb7477476c0", false)[0];
            

            //For the signature (and encrypt) we use eHealth certificates
            sign = eh;

            //For the session we use eHealth certificate
            session = eh;

            //For authentication we use eid certificate (but since that does notwork, ticket 2-3RKM9C, we use the eHealth certificfate.
            auth = eh;
        }

        [TestMethod]
        public void ConfigDoctorViaCode()
        {
            //Create SSOBinding
            var ssoBinding = new SsoBinding();
            ssoBinding.Security.Mode = WSFederationHttpSecurityMode.Message;
            ssoBinding.Security.Message.IssuedKeyType = SecurityKeyType.AsymmetricKey;
            ssoBinding.Security.Message.NegotiateServiceCredential = false;
            ssoBinding.Security.Message.EstablishSecurityContext = false;

            ssoBinding.Security.Message.IssuerAddress = new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService");
            ssoBinding.Security.Message.IssuerBinding = new StsBinding();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:person:ssin\">" +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">79021802145</saml:AttributeValue>" +
                "</saml:Attribute>");
            ssoBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);
            doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:ehealth:1.0:certificateholder:person:ssin\">" +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">79021802145</saml:AttributeValue>" +
                "</saml:Attribute>");
            ssoBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);

            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11"));

            //Creating basic https binding
            BasicHttpBinding httpsBinding = new BasicHttpBinding();
            httpsBinding.Security.Mode = BasicHttpSecurityMode.Transport;

            //Create the Consult proxy
            Chap4AgreementConsultationPortTypeClient consult = new Chap4AgreementConsultationPortTypeClient(ssoBinding, new EndpointAddress("https://services-acpt.ehealth.fgov.be/ChapterIV/ChapterIVAgreementConsultation/v1"));
            consult.Endpoint.Behaviors.Remove<ClientCredentials>();
            consult.Endpoint.Behaviors.Add(new SsoClientCredentials());
            consult.Endpoint.Behaviors.Add(new SessionBehavior(session, TimeSpan.FromHours(1), typeof(MemorySessionCache), null));
            consult.ClientCredentials.ClientCertificate.Certificate = auth; //must be put after the behavior

            //Create KGSS proxy
            KgssPortTypeClient kgss = new KgssPortTypeClient(httpsBinding, new EndpointAddress("https://services-acpt.ehealth.fgov.be/Kgss/v1"));

            //Create ETK Depot proxy
            EtkDepotPortTypeClient etkDepot = new EtkDepotPortTypeClient(httpsBinding, new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1"));

            //Create self
            SecurityInfo self = SecurityInfo.Create(sign, StoreLocation.CurrentUser, etkDepot);

            //Create Consult postmaster
            ConsultPostMaster postmaster = new ConsultPostMaster(self, consult, etkDepot, kgss);
            postmaster.VerifyEtk = false;

            //prepare the input
            InputParameterData parameters = new InputParameterData();
            parameters.CommonInput = new CommonInputType();
            parameters.CommonInput.Request = new RequestType1();
            parameters.CommonInput.Request.IsTest = true;
            parameters.CommonInput.Origin = new OriginType();
            parameters.CommonInput.Origin.Package = new PackageType();
            parameters.CommonInput.Origin.Package.License = new LicenseType();
            parameters.CommonInput.Origin.Package.License.Username = "ehi"; //provide you own license
            parameters.CommonInput.Origin.Package.License.Password = "eHIpwd05"; //provide your own password
            parameters.CommonInput.Origin.CareProvider = new CareProviderType();
            parameters.CommonInput.Origin.CareProvider.Nihii = new NihiiType();
            parameters.CommonInput.Origin.CareProvider.Nihii.Quality = "doctor";
            parameters.CommonInput.Origin.CareProvider.Nihii.Value = new ValueRefString();
            parameters.CommonInput.Origin.CareProvider.Nihii.Value.Value = "19997341001";
            parameters.CommonInput.Origin.CareProvider.PhysicalPerson = new IdType();
            parameters.CommonInput.Origin.CareProvider.PhysicalPerson.Ssin = new ValueRefString();
            parameters.CommonInput.Origin.CareProvider.PhysicalPerson.Ssin.Value = "79021802145";
            parameters.RecordCommonInput = new RecordCommonInputType();
            parameters.RecordCommonInput.InputReferenceSpecified = true;
            parameters.RecordCommonInput.InputReference = 20101112100503;
            parameters.AgreementStartDate = new DateTime(2010, 08, 06, 0, 0, 0, DateTimeKind.Utc);
            parameters.CareReceiverId = new CareReceiverIdType();
            parameters.CareReceiverId.Ssin = "79021802145";

            //send the request
            X509Certificate2 sender;
            Tuple<Stream, OutputParameterData> response = postmaster.Transfer(new FileStream("request_consult_physician.xml", FileMode.Open), parameters, out sender);
        }
    }
}
