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
using Egelke.EHealth.Client.Services.Mda;
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

        public Memberdata()
        {
            ECDSAConfig.Init(); //needed to enable ECDSA globally.
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            wstEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");

            mdaEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/MyCareNet/MemberData/v1");

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
            //configure the binding with the STS service
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));

            //configure the client for the MDA service
            var mcnMda = new McnMdaClient(binding, mdaEp, loggerFactory.CreateLogger<McnMdaClient>())
            {
                IsTest = true,
                License = new LicenseType()
                {
                    Username = File.ReadAllText("files/license.txt"),
                    Password = File.ReadAllText("files/license.pwd")
                },
                CareProvider = new CareProviderType()
                {
                    PhysicalPerson = new IdType1()
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
            };
            mcnMda.ClientCredentials.ClientCertificate.Certificate = idCert;
            mcnMda.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            //Use the interface
            IMda target = mcnMda;

            //Create the query
            XmlElement query = target.CreateQuery(
                File.ReadAllText("files/patient.ssin"),
                DateTime.Today.AddDays(-2),
                DateTime.Today.AddDays(-1),
                Facet.CreateInsurability(Dimension.VALUE_INFORMATION, Dimension.VALUE_OTHER)
                //,Facet.CreateCarePath(Dimension.VALUE_DIABETES, Dimension.VALUE_RENALINSUFFICIENCY)
                );

            //Consult to get the assertions
            var assertions = target.Consult(query);

            //Verify
            Assert.NotEmpty(assertions);
        }
    }
}