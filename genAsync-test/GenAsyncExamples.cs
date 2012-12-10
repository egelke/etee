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

namespace Egelke.EHealth.Client.GenAsyncTest
{
    [TestClass]
    public class GenAsyncExamples
    {
        private static X509Certificate2 sign;
        private static TimeStampAuthorityClient tsaViaConfig;

        [ClassInitialize]
        public static void MyClassInitialize(TestContext testContext)
        {
            //Select the signing certificate
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            sign = store.Certificates.Find(X509FindType.FindByThumbprint, "2819be79150fe6a5ea155125348ea00fc76b24ab", false)[0];

            //Create an instance to the eHealth TSA
            tsaViaConfig = new TimeStampAuthorityClient("TSA");
        }

        [TestMethod]
        public void ConfigViaConfig()
        {
            GenericAsyncClient client = new GenericAsyncClient("IO100");

            DoTest(client);
        }

        [TestMethod]
        public void ConfigViaCode()
        {
            //GenericAsyncClient client = new GenericAsyncClient(

            //load certificate (eid)
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection canidateCerts = store.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.NonRepudiation, true);
            X509Certificate2Collection selectedCerts = X509Certificate2UI.SelectFromCollection(canidateCerts, "Select cert", "Select your signing cert", X509SelectionFlag.SingleSelection);
        }

        private void DoTest(GenericAsyncClient client)
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
            xigner.TimestampProvider = new EHealthTimestampProvider(tsaViaConfig);
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

            TAck nipAck = client.post(commonInput, blob, xadesParam);

            Assert.AreEqual("urn:nip:tack:result:major:success", nipAck.ResultMajor);
        }
    }
}
