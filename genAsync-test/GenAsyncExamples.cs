using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Egelke.EHealth.Client.GenAsync;
using System.IO.Compression;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using IM.Xades;
using IM.Xades.TSA.DSS;
using IM.Xades.TSA;
using System.Security.Cryptography.Xml;
using IM.Xades.Extra;
using System.Xml.Serialization;
using System.Xml;
using Siemens.EHealth.Client.Sso;
using System.ServiceModel;
using Siemens.EHealth.Client.Sso.Sts;
using System.ServiceModel.Security.Tokens;
using System.IdentityModel.Tokens;
using System.ServiceModel.Description;
using Siemens.EHealth.Client.Sso.WA;
using System.Threading;

namespace Egelke.EHealth.Client.GenAsyncTest
{
    [TestClass]
    public class GenAsyncExamples
    {
        private static X509Certificate2 sign;
        private static X509Certificate2 auth;
        private static X509Certificate2 session;
        private static X509Certificate2 tsa;
        private static X509Certificate2 tsaTrust;

        [ClassInitialize]
        public static void MyClassInitialize(TestContext testContext)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            //Select the hospital certificate, should be used for all 4 certs (but we can't, see below)
            X509Certificate2 hospital = store.Certificates.Find(X509FindType.FindByThumbprint, "415442ca384c853231e203fafa9a436f33b4043b", false)[0];

            //For the signature and authentication we can use the hosptial certificate
            sign = hospital;
            auth = hospital;

            //Since our hospital can't use TSA, we use a different (you should use the hosptial cert)
            tsa = store.Certificates.Find(X509FindType.FindByThumbprint, "9c4227f1b9c7a52823829837f1a2e80690da8010", false)[0];
            
            //Since the hospital certificates aren't from an actual CA, MCN does not allow them (you should use the hosptial cert in production)
            session = store.Certificates.Find(X509FindType.FindByThumbprint, "c6c3cba1000c955c2e6289c6eb40bbb7477476c0", false)[0];

            //We trust eHealth for TSA
            tsaTrust = new X509Certificate2("tsa.crt");
        }

        [TestMethod]
        public void ConfigViaConfig()
        {
            GenericAsyncClient client = new GenericAsyncClient("IO100");
            TimeStampAuthorityClient tsaClient = new TimeStampAuthorityClient("TSA");

            DoTest(client, tsaClient);
        }

        [TestMethod]
        public void ConfigViaCode()
        {
            var ssoBinding = new SsoBinding();
            ssoBinding.MessageEncoding = System.ServiceModel.WSMessageEncoding.Mtom;
            ssoBinding.MaxReceivedMessageSize = 100L * 1024L * 1024L; //100MB
            ssoBinding.Security.Mode = WSFederationHttpSecurityMode.TransportWithMessageCredential;
            ssoBinding.Security.Message.IssuedKeyType = SecurityKeyType.AsymmetricKey;
            ssoBinding.Security.Message.NegotiateServiceCredential = false;
            ssoBinding.Security.Message.EstablishSecurityContext = false;

            ssoBinding.Security.Message.IssuerAddress = new EndpointAddress("https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService");
            ssoBinding.Security.Message.IssuerBinding = new StsBinding();

            XmlDocument doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:ehealth:1.0:hospital:nihii-number\">" +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">71022212</saml:AttributeValue>" +
                "</saml:Attribute>");
            ssoBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);
            doc = new XmlDocument();
            doc.LoadXml("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:ehealth:1.0:certificateholder:hospital:nihii-number\">" +
                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">71022212</saml:AttributeValue>" +
                "</saml:Attribute>");
            ssoBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);

            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:hospital:nihii-number"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:hospital:nihii-number"));
            ssoBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:ehealth:1.0:certificateholder:hospital:nihii-number:recognisedhospital:boolean"));

            ssoBinding.ReaderQuotas.MaxStringContentLength = 100 * 1024 * 1024; //100MB

            GenericAsyncClient client = new GenericAsyncClient(ssoBinding, new EndpointAddress("urn:nip:destination:io:100")); //indicates the destination IO

            client.Endpoint.Behaviors.Remove<ClientCredentials>();
            client.Endpoint.Behaviors.Add(new SsoClientCredentials());
            client.Endpoint.Behaviors.Add(new SessionBehavior(session , TimeSpan.FromHours(1), typeof(FileSessionCache), null));
            client.Endpoint.Behaviors.Add(new ClientViaBehavior(new Uri("https://dev.mycarenet.be/mycarenet-ws/async/generic/adm"))); //the actual MCN url

            client.ClientCredentials.ClientCertificate.Certificate = auth; //must be put after the behavior

            TimeStampAuthorityClient tsaClient = new TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/timestampauthority_1_5/timestampauthority"));
            tsaClient.Endpoint.Behaviors.Remove<ClientCredentials>();
            tsaClient.Endpoint.Behaviors.Add(new OptClientCredentials());

            tsaClient.ClientCredentials.ClientCertificate.Certificate = tsa; //must be put after the behavior

            DoTest(client, tsaClient);
        }

        private void DoTest(GenericAsyncClient client, TimeStampAuthorityClient tsaClient)
        {
            //Create common input with info about the requestor, must match SAML
            CommonInputType commonInput = new CommonInputType();
            commonInput.InputReference = "TADM1234567890";
            commonInput.Request = new RequestType();
            commonInput.Request.IsTest = true;
            commonInput.Origin = new OrigineType();
            commonInput.Origin.Package = new PackageType();
            commonInput.Origin.Package.Name = "eH-I Test";
            commonInput.Origin.Package.License = new LicenseType();
            commonInput.Origin.Package.License.Username = "ehi"; //provide you own license
            commonInput.Origin.Package.License.Password = "eHIpwd05"; //provide your own password
            commonInput.Origin.SiteID = "01"; //CareNet Gateway ID.
            commonInput.Origin.CareProvider = new CareProviderType();
            commonInput.Origin.CareProvider.Nihii = new NihiiType();
            commonInput.Origin.CareProvider.Nihii.Quality = "hospital";
            commonInput.Origin.CareProvider.Nihii.Value = "71022212000";
            commonInput.Origin.CareProvider.Organization = new IdType();
            commonInput.Origin.CareProvider.Organization.Nihii = commonInput.Origin.CareProvider.Nihii;

            //create blob value
            Stream raw = new MemoryStream(Encoding.ASCII.GetBytes("This is not a business message and I don't mean it in Magritte way")); //you might use a file instead
            MemoryStream deflated = new MemoryStream();
            DeflateStream deflater = new DeflateStream(deflated, CompressionMode.Compress, true);
            raw.CopyTo(deflater);
            deflater.Flush();
            deflater.Close();
            
            //create blob
            Blob blob = new Blob();
            blob.MessageName = "ADM";
            blob.Id = "_" + Guid.NewGuid().ToString();
            blob.ContentType = "text/plain";
            blob.Value = deflated.ToArray();

            //Create Xml with the blob inside it to sign.
            XmlDocument signDoc;
            using(MemoryStream signDocStream = new MemoryStream()) {
                XmlWriter signDocWriter = XmlWriter.Create(signDocStream);
                signDocWriter.WriteStartElement("root");

                XmlSerializer serializer = new XmlSerializer(typeof(Blob), new XmlRootAttribute("Detail"));
                serializer.Serialize(signDocWriter, blob);

                signDocWriter.WriteEndElement();
                signDocWriter.Flush();

                signDocStream.Seek(0, SeekOrigin.Begin);
                signDoc = new XmlDocument();
                signDoc.PreserveWhitespace = true;
                signDoc.Load(signDocStream);
            }

            //create the xades-t
            var xigner = new XadesCreator(sign);
            xigner.TimestampProvider = new EHealthTimestampProvider(tsaClient);
            xigner.DataTransforms.Add(new XmlDsigBase64Transform());
            xigner.DataTransforms.Add(new OptionalDeflateTransform());
            XmlElement xades = xigner.CreateXadesT(signDoc, blob.Id);

            //conver the xades-t to byte array
            MemoryStream xadesSteam = new MemoryStream();
            using (var writer = XmlWriter.Create(xadesSteam))
            {
                xades.WriteTo(writer);
            }

            //Create the Base64 structure
            base64Binary xadesParam = new base64Binary();
            xadesParam.contentType = "text/xml";
            xadesParam.Value = xadesSteam.ToArray();

            //Send the message
            Thread.Sleep(1000); //sleep to let the eID recover :(
            TAck nipAck = client.post(commonInput, blob, xadesParam);

            //check if the messages was correctly send
            Assert.AreEqual("urn:nip:tack:result:major:success", nipAck.ResultMajor);

            //Get any waiting responses
            MsgQuery msgQuery = new MsgQuery();
            msgQuery.Max = 1; //best to specify to avoid quota exceeds or memory issues
            msgQuery.Include = true;
            Query tackQuery = new Query();
            tackQuery.Max = 10; //best to specify, but since they are smaller we can handle more
            tackQuery.Include = true;

            //Get the messages & tACK
            Thread.Sleep(1000); //sleep to let the eID recover :(
            Responses rsp = client.get(commonInput.Origin, msgQuery, tackQuery);

            //Collect the hash values of the messages & the tack
            //Should be a list of bytes arrays, but WCF isn't that smart so you need to do the encoding (base64, sperated by spaces)
            StringBuilder msgHashValues = new StringBuilder();
            if (rsp.MsgResponse != null)
            {
                foreach (MsgResponse msgRsp in rsp.MsgResponse)
                {
                    //Parse the xades, and rework it to a doc that contains the detail & xades.
                    XmlDocument verifyDoc;
                    using (MemoryStream verifyDocStream = new MemoryStream())
                    {
                        //Create new doc with element root
                        XmlWriter verifyDocWriter = XmlWriter.Create(verifyDocStream);
                        verifyDocWriter.WriteStartElement("root", "urn:dummy");

                        //Add blob (detail)
                        XmlSerializer serializer = new XmlSerializer(typeof(Blob), "urn:be:cin:types:v1");
                        serializer.Serialize(verifyDocWriter, msgRsp.Detail);

                        //Add xades-T
                        XmlDocument xadesDoc = new XmlDocument();
                        xadesDoc.PreserveWhitespace = true;
                        xadesDoc.Load(new MemoryStream(msgRsp.Xadest.Value));
                        xadesDoc.DocumentElement.WriteTo(verifyDocWriter);

                        verifyDocWriter.WriteEndElement();
                        verifyDocWriter.Flush();

                        //Reload the result
                        verifyDocStream.Seek(0, SeekOrigin.Begin);
                        verifyDoc = new XmlDocument();
                        verifyDoc.PreserveWhitespace = true;
                        verifyDoc.Load(verifyDocStream);

                        //Validate the doc
                        XmlElement prop = (XmlElement) XadesTools.FindXadesProperties(verifyDoc.DocumentElement)[0];
                        XadesVerifier verifier = new XadesVerifier();
                        verifier.RevocationMode = X509RevocationMode.NoCheck; //only for testing
                        verifier.TrustedTsaCert = tsaTrust;
                        SignatureInfo info = verifier.Verify(verifyDoc, prop);

                        //check info (time & certificate) to your own rules.
                    }

                    if (msgHashValues.Length != 0) msgHashValues.Append(" ");
                    msgHashValues.Append(Convert.ToBase64String(msgRsp.Detail.HashValue));
                }
            }
            List<String> resend = new List<string>();
            StringBuilder tackContents = new StringBuilder();
            if (rsp.TAckResponse != null)
            {
                foreach (TAckResponse tackRsp in rsp.TAckResponse)
                {
                    //Parse the xades, and rework it to a doc that contains the detail & xades.
                    XmlDocument verifyDoc;
                    using (MemoryStream verifyDocStream = new MemoryStream())
                    {
                        //Create new doc with element root
                        XmlWriter verifyDocWriter = XmlWriter.Create(verifyDocStream);
                        verifyDocWriter.WriteStartElement("root", "urn:dummy");

                        //Add blob (detail)
                        XmlSerializer serializer = new XmlSerializer(typeof(TAck), "urn:be:cin:nip:async:generic");
                        serializer.Serialize(verifyDocWriter, tackRsp.TAck);

                        //Add xades-T
                        XmlDocument xadesDoc = new XmlDocument();
                        xadesDoc.PreserveWhitespace = true;
                        xadesDoc.Load(new MemoryStream(tackRsp.Xadest.Value));
                        xadesDoc.DocumentElement.WriteTo(verifyDocWriter);

                        verifyDocWriter.WriteEndElement();
                        verifyDocWriter.Flush();

                        //Reload the result
                        verifyDocStream.Seek(0, SeekOrigin.Begin);
                        verifyDoc = new XmlDocument();
                        verifyDoc.PreserveWhitespace = true;
                        verifyDoc.Load(verifyDocStream);

                        //Validate the doc
                        XmlElement prop = (XmlElement)XadesTools.FindXadesProperties(verifyDoc.DocumentElement)[0];
                        XadesVerifier verifier = new XadesVerifier();
                        verifier.RevocationMode = X509RevocationMode.NoCheck; //only for testing
                        verifier.TrustedTsaCert = tsaTrust;
                        SignatureInfo info = verifier.Verify(verifyDoc, prop);

                        //check info (time & certificate) to your own rules.
                    }

                    //send failed, resend later.
                    if ("urn:nip:tack:result:major:success" != tackRsp.TAck.ResultMajor)
                    {
                        resend.Add(tackRsp.TAck.AppliesTo);
                    }

                    if (tackContents.Length != 0) tackContents.Append(" ");
                    tackContents.Append(Convert.ToBase64String(tackRsp.TAck.Value)); //the content of the tAck is already a hash...
                }
            }

            //Confirm the received messages & tack
            Thread.Sleep(1000); //sleep to let the eID recover :(
            client.confirm(commonInput.Origin, msgHashValues.ToString(), tackContents.ToString());

            //We should not have anything to resend
            Assert.AreEqual(0, resend.Count);
        }
    }
}
