using System;
using System.IdentityModel.Claims;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Pki.ECDSA;
using Egelke.EHealth.Client.Sts;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class Memberdata
    {
        private ILoggerFactory loggerFactory;

        private EndpointAddress wstEp;

        private EndpointAddress mdaEp;

        private X509Certificate2 idCert;

        private X509Certificate2 sessionCert;

        private string ssin;

        private string nihii11;

        private ILogger<Memberdata> logger;

        public Memberdata()
        {
            ECDSAConfig.Init(); //needed to enable ECDSA globally.
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
            logger = loggerFactory.CreateLogger<Memberdata>();

            //wstEp = new EndpointAddress("https://services-int.ehealth.fgov.be/IAM/SecurityTokenService/v1");
            wstEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");

            mdaEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/MyCareNet/MemberData/v1");


            //var p12 = new EHealthP12("files/ehealth-01050399864-int.p12", File.ReadAllText("files/ehealth-01050399864-int.p12.pwd"));
            //var p12 = new EHealthP12("files/ehealth-79021802145-acc.p12", File.ReadAllText("files/ehealth-79021802145-acc.p12.pwd"));
            var p12 = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));
            idCert = p12["authentication"];
            sessionCert = null;

            Match match = Regex.Match(idCert.Subject, @"(SSIN|SERIALNUMBER)=(\d{11})");
            Assert.True(match.Success, "need an ssin in the cert subject (is an eID available?)");
            ssin = match.Groups[2].Value;


            nihii11 = "19997341001";
        }

        [Fact]
        public void DoctorCallingMycarenetSync()
        {
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));


            ChannelFactory<MycarenetMemberDataPortType> channelFactory = new ChannelFactory<MycarenetMemberDataPortType>(binding, mdaEp);
            channelFactory.Credentials.ClientCertificate.Certificate = idCert;
            channelFactory.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            MycarenetMemberDataPortType mdaClient = channelFactory.CreateChannel();

            string reqId = "TMDA" + DateTime.Now.ToString("yyyyMMddHHmmss");

            XNamespace ns_samlp = "urn:oasis:names:tc:SAML:2.0:protocol";
            XNamespace ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion";
            XNamespace ns_ext = "urn:be:cin:nippin:memberdata:saml:extension";
            XNamespace ns_xsi = "http://www.w3.org/2001/XMLSchema-instance";
            var reqBody = new XDocument(
                    new XElement(ns_samlp+ "AttributeQuery",
                        new XAttribute("ID", "_" +reqId),
                        new XAttribute("Version", "2.0"),
                        new XAttribute("IssueInstant", DateTime.UtcNow.ToString("s")),
                        new XAttribute(XNamespace.Xmlns + "samlp", ns_samlp),
                        new XAttribute(XNamespace.Xmlns + "saml", ns_saml),
                        new XAttribute(XNamespace.Xmlns + "ext", ns_ext),
                        new XAttribute(XNamespace.Xmlns + "xsi", ns_xsi),
                        new XElement(ns_saml+ "Issuer",
                            new XAttribute("Format", "urn:be:cin:nippin:nihii11"),
                            nihii11
                        ),
                        new XElement(ns_samlp + "Extensions", 
                            new XAttribute(ns_xsi + "type", "ext:ExtensionsType"),
                            new XElement(ns_ext + "Facet",
                                new XAttribute("id", "urn:be:cin:nippin:insurability"),
                                new XElement("Dimension",
                                    new XAttribute("id", "requestType"),
                                    "information"
                                ),
                                new XElement("Dimension",
                                    new XAttribute("id", "contactType"),
                                    "other"
                                )
                            )
                        ),
                        new XElement(ns_saml + "Subject",
                            new XElement(ns_saml + "NameID",
                                new XAttribute("Format", "urn:be:fgov:person:ssin"),
                                File.ReadAllText("files/patient.ssin")
                            ),
                            new XElement(ns_saml + "SubjectConfirmation",
                                new XAttribute("Method", "urn:be:cin:nippin:memberIdentification"),
                                new XElement(ns_saml + "SubjectConfirmationData",
                                    new XAttribute("NotBefore", DateTime.Today.AddDays(-2).ToString("s")),
                                    new XAttribute("NotOnOrAfter", DateTime.Today.AddDays(-1).ToString("s"))
                                )
                            )
                        )
                    )
                );
            var reqBodyStream = new MemoryStream();
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false), // Disable BOM
                Indent = true,                      // Optional: pretty print
                OmitXmlDeclaration = false,         // Include XML declaration
                IndentChars = "  ",
                NewLineHandling = NewLineHandling.Replace
            };
            using (var writer = XmlWriter.Create(reqBodyStream, settings))
            {
                reqBody.Save(writer);
            }
            logger.LogDebug("Request body: {0}", Encoding.UTF8.GetString( reqBodyStream.ToArray() ) );


            var req = new memberDataConsultationRequest()
            {
                MemberDataConsultationRequest1 = new SendRequestMemberDataType()
                {
                    Id = "_" + Guid.NewGuid().ToString(),
                    CommonInput = new CommonInputType()
                    {
                        InputReference = reqId,
                        Request = new RequestType1()
                        {
                            IsTest = true,
                        },
                        Origin = new OriginType()
                        {
                            Package = new PackageType()
                            {
                                License = new LicenseType()
                                {
                                    Username = File.ReadAllText("files/license.txt"),
                                    Password = File.ReadAllText("files/license.pwd")
                                }
                            },
                            CareProvider = new CareProviderType()
                            {
                                PhysicalPerson = new IdType()
                                {
                                    Ssin = new ValueRefString()
                                    {
                                        Value = ssin
                                    }
                                },
                                Nihii = new NihiiType()
                                {
                                    Quality = "doctor",
                                    Value = new ValueRefString()
                                    {
                                        Value = nihii11
                                    }
                                }
                            }
                        }
                    },
                    Detail = new BlobType()
                    {
                        ContentType = "text/xml",
                        ContentEncoding = "none",
                        Value = reqBodyStream.ToArray()
                    }
                }
            };
            memberDataConsultationResponse rsp = mdaClient.memberDataConsultation(req);

            byte[] rspBody = rsp.MemberDataConsultationResponse1.Return.Detail.Value;

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(new MemoryStream(rspBody));

            var rspBodyStream = new MemoryStream();
            using (var writer = XmlWriter.Create(rspBodyStream, settings))
            {
                doc.Save(rspBodyStream);
                logger.LogDebug("Response body: {0}", Encoding.UTF8.GetString(rspBodyStream.ToArray()));
            }

            XmlNamespaceManager nsMngr = new XmlNamespaceManager(doc.NameTable);
            nsMngr.AddNamespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");
            nsMngr.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");

            string statusCode = doc.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value", nsMngr).Value;
            Assert.Equal("urn:oasis:names:tc:SAML:2.0:status:Success", statusCode);
        }
    }
}