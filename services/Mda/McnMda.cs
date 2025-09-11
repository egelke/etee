using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.Mda
{

    public class McnMda : ClientBase<MycarenetMemberDataPortType>, IMda
    {
        private const string SAML2P_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

        private const string SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

        private const string CIN_TYPES_NS = "urn:be:cin:types:v1";

        private readonly ILogger<McnMda> _logger;

        public LicenseType License { get; set; }

        public CareProviderType CareProvider { get; set; }

        public bool IsTest { get; set; } = true;


        public McnMda(ILogger<McnMda> logger = null)
            : base()
        {
            _logger = logger;
        }

        public McnMda(ServiceEndpoint endpoint, ILogger<McnMda> logger = null)
            : base(endpoint)
        {
            _logger = logger;
        }

        public McnMda(Binding binding, EndpointAddress remoteAddress, ILogger<McnMda> logger = null) 
            : base(binding, remoteAddress)
        {
            _logger = logger;
        }

        public XmlElement CreateQuery(string ssin, DateTime start, DateTime end, params Facet[] facets)
        {
            string reqId = (IsTest ? "T" : "P") + "MDA" + DateTime.Now.ToString("yyyyMMddHHmmss");

            XNamespace ns_samlp = SAML2P_NS;
            XNamespace ns_saml = SAML2_NS;
            XNamespace ns_xsi = "http://www.w3.org/2001/XMLSchema-instance";
            var reqBody = new XDocument(
                    new XElement(ns_samlp + "AttributeQuery",
                        new XAttribute("ID", "_" + reqId),
                        new XAttribute("Version", "2.0"),
                        new XAttribute("IssueInstant", DateTime.UtcNow.ToString("s")),
                        new XAttribute(XNamespace.Xmlns + "samlp", ns_samlp),
                        new XAttribute(XNamespace.Xmlns + "saml", ns_saml),
                        new XElement(ns_saml + "Issuer",
                            new XAttribute("Format", "urn:be:cin:nippin:nihii11"),
                            CareProvider.Nihii.Value.Value
                        ),
                        new XElement(ns_samlp + "Extensions",
                            new XAttribute(XNamespace.Xmlns + "ext", Facet.EXT_NS),
                            new XAttribute(XNamespace.Xmlns + "xsi", ns_xsi),
                            new XAttribute(ns_xsi + "type", "ext:ExtensionsType"),
                            facets.Select(f => f.ToXElement()).ToArray()
                        ),
                        new XElement(ns_saml + "Subject",
                            new XElement(ns_saml + "NameID",
                                new XAttribute("Format", "urn:be:fgov:person:ssin"),
                                ssin
                            ),
                            new XElement(ns_saml + "SubjectConfirmation",
                                new XAttribute("Method", "urn:be:cin:nippin:memberIdentification"),
                                new XElement(ns_saml + "SubjectConfirmationData",
                                    new XAttribute("NotBefore", start.ToString("s")),
                                    new XAttribute("NotOnOrAfter", end.ToString("s"))
                                )
                            )
                        )
                    )
                );

            var xmlDoc = new XmlDocument();
            using (var reader = reqBody.CreateReader())
            {
                xmlDoc.Load(reader);
            }
            return xmlDoc.DocumentElement;
        }

        public IEnumerable<XmlElement> Consult(XmlElement query)
        {
            XmlNamespaceManager reqMngr = new XmlNamespaceManager(query.OwnerDocument.NameTable);
            reqMngr.AddNamespace("saml2p", SAML2P_NS);
            reqMngr.AddNamespace("saml2", SAML2_NS);

            string reqId = query.SelectSingleNode("/saml2p:AttributeQuery/@ID", reqMngr)?.Value?.Substring(1);

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
                query.WriteTo(writer);
            }

            var req = new SendRequestMemberDataType()
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
                            License = License
                        },
                        CareProvider = CareProvider
                    }
                },
                Detail = new BlobType()
                {
                    ContentType = "text/xml",
                    ContentEncoding = "none",
                    Value = reqBodyStream.ToArray()
                }
            };

            _logger?.LogInformation("Calling MyCareNet MDA, ref={0}", req.CommonInput.InputReference);
            _logger?.LogDebug("Calling MyCareNet MDA {0} with query: {1}", req.CommonInput.InputReference, query.OuterXml);

            ResponseReturnType rsp = Channel.memberDataConsultation(
                    new memberDataConsultationRequest() {  MemberDataConsultationRequest1 = req }
                )?.MemberDataConsultationResponse1?.Return;
            
            _logger?.LogInformation("Received response for {0} with out-ref {1} and nip-ref {2}",
                req.CommonInput.InputReference,
                rsp?.CommonOutput?.OutputReference,
                rsp?.CommonOutput?.NIPReference);

            byte[] rspBody = rsp?.Detail?.Value;
            _logger?.LogDebug("Recieved respronse for {0}: {1}",
                req.CommonInput.InputReference,
                Encoding.UTF8.GetString(rspBody));

            var rspDoc = new XmlDocument();
            rspDoc.PreserveWhitespace = true;
            rspDoc.Load(new MemoryStream(rspBody));

            XmlNamespaceManager rspMngr = new XmlNamespaceManager(rspDoc.NameTable);
            rspMngr.AddNamespace("saml2p", SAML2P_NS);
            rspMngr.AddNamespace("saml2", SAML2_NS);
            rspMngr.AddNamespace("t", CIN_TYPES_NS);

            string statusCode = rspDoc.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value", rspMngr)?.Value;
            if (statusCode != "urn:oasis:names:tc:SAML:2.0:status:Success")
            {
                string statusMessage = rspDoc.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusMessage", rspMngr)?.InnerText;

                string faultCode = rspDoc.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusDetail/Fault/t:FaultCode", rspMngr)?.InnerText;
                string faultMessage = rspDoc.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusDetail/Fault/t:Message", rspMngr)?.InnerText;

                throw new ServiceException(faultCode ?? statusCode, faultMessage ?? statusMessage);
            }

            return rspDoc.SelectNodes("/saml2p:Response/saml2:Assertion", rspMngr).Cast<XmlElement>();
        }
    }
}
