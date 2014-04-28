using System;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Sso;
using System.ServiceModel;
using System.IdentityModel.Tokens;
using Egelke.EHealth.Client.Sso.Sts;
using System.Xml;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;
using Egelke.EHealth.Client.ChapterIV;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using NUnit.Framework;

namespace Egelke.EHealth.Client.ChapterIVTest
{

    [TestFixture]
    public class ConsultExample
    {
        private X509Certificate2 sign;
        private X509Certificate2 auth;
        private X509Certificate2 session;

        [TestFixtureSetUp]
        public void MyClassInitialize()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            //Select the care provider certificate issued by eHealth
            X509Certificate2 eh = store.Certificates.Find(X509FindType.FindByThumbprint, "566fd3fe13e3ab185a7224bcec8ad9cffbf9e9c2", false)[0];
            X509Certificate2 eid = store.Certificates.Find(X509FindType.FindByThumbprint, "1ac02600f2f2b68f99f1e8eeab2e780470e0ea4c", false)[0];
            

            //For the signature (and encrypt) we use eHealth certificates
            sign = eh;

            //For the session we use eHealth certificate
            session = eh;

            //For authentication we use eid certificate
            auth = eid;
        }

        

        [Test]
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
            //parameters.CommonInput.Origin.Package.License.Username = "ehi"; //provide you own license
            //parameters.CommonInput.Origin.Package.License.Password = "eHIpwd05"; //provide your own password
            parameters.CommonInput.Origin.Package.License.Username = "siemens"; //provide you own license
            parameters.CommonInput.Origin.Package.License.Password = "n7z6Y(S8+X"; //provide your own password

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
            parameters.AgreementStartDate = new DateTime(2013, 04, 01, 0, 0, 0, DateTimeKind.Utc);
            parameters.CareReceiverId = new CareReceiverIdType();
            parameters.CareReceiverId.Ssin = "01093008501";

            //send the request
            X509Certificate2 sender;
            Tuple<Stream, OutputParameterData> response = postmaster.Transfer(new FileStream("request_consult_physician.xml", FileMode.Open), parameters, out sender);

            WriteFormattedXml(response.Item1);

            //Chech for business responses
            XmlDocument responseDoc = new XmlDocument();
            XmlNamespaceManager nsmgr =  new XmlNamespaceManager(responseDoc.NameTable);
            nsmgr.AddNamespace("ns", "http://www.ehealth.fgov.be/medicalagreement/core/v1");
            nsmgr.AddNamespace("kmehr", "http://www.ehealth.fgov.be/standards/kmehr/schema/v1");
            responseDoc.Load(response.Item1);
            XmlNodeList errorList = responseDoc.SelectNodes("/ns:kmehrresponse/ns:acknowledge/ns:error", nsmgr);
            if (errorList.Count > 0)
            {
                StringBuilder errorMsg = new StringBuilder();
                foreach (XmlNode error in errorList)
                {
                    errorMsg.Append(error.SelectSingleNode("./kmehr:cd", nsmgr).InnerText)
                        .Append(": ")
                        .Append(error.SelectSingleNode("./kmehr:description", nsmgr).InnerText)
                        .Append(" (")
                        .Append(error.SelectSingleNode("./kmehr:url", nsmgr).InnerText)
                        .AppendLine(")");
                }
                Assert.Inconclusive(errorMsg.ToString());
            }
        }

        private static void WriteFormattedXml(Stream input)
        {
            XmlDocument document = new XmlDocument();
            document.Load(input);

            using (StringWriter mStream = new StringWriter())
            {
                var settings = new XmlWriterSettings();
                settings.Indent = true;

                XmlWriter writer = XmlWriter.Create(mStream, settings);
                document.WriteContentTo(writer);
                writer.Flush();
                mStream.Flush();
                System.Console.WriteLine(mStream.ToString());
            }
            input.Seek(0, SeekOrigin.Begin);
        }
    }
}
