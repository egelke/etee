using Egelke.Wcf.Client;
using Egelke.Wcf.Client.Helper;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Xunit;

namespace library_core_tests
{

    public class EidV18 : IDisposable
    {

        private byte[] clearMsg;

        X509Certificate2 eid;
        RSA privateRsa;
        RSA publicRsa;
        ECDsa privateEcdsa;
        ECDsa publicEcdsa;

        public EidV18()
        {
            ECDsaConfig.Init();
            clearMsg = System.Text.Encoding.UTF8.GetBytes("Hello world");

            eid = Config.Instance.Certificate;
            privateRsa = eid.GetRSAPrivateKey();
            publicRsa = eid.GetRSAPublicKey();
            privateEcdsa = eid.GetECDsaPrivateKey();
            publicEcdsa = eid.GetECDsaPublicKey();
        }

        [Fact]
        public void Sign()
        {

            byte[] signature;
            if (privateRsa != null)
            {
                signature = privateRsa.SignData(clearMsg, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else if (privateEcdsa != null)
            {
                signature = privateEcdsa.SignData(clearMsg, HashAlgorithmName.SHA256);
            }
            else
            {
                signature = null;
            }
            Assert.NotNull(signature);

            if (publicRsa != null)
            {
                Assert.True(publicRsa.VerifyData(clearMsg, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            else if (publicEcdsa != null)
            {
                Assert.True(publicEcdsa.VerifyData(clearMsg, signature, HashAlgorithmName.SHA256));
            }
        }


        [Fact]
        public void SignXml()
        {

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load("test.xml");

            var signedXml = new SignedXml(doc);
            if (privateRsa != null)
            {
                signedXml.SigningKey = privateRsa;
            }
            else
            {
                signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"; //required for ECDSA
                signedXml.SigningKey = privateEcdsa;
            }

            Reference reference = new Reference();
            reference.Uri = "#_1";

            var transform = new XmlDsigExcC14NTransform();
            reference.AddTransform(transform);

            signedXml.AddReference(reference);
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(eid));

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();

            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));


            XmlTextWriter xmltw = new XmlTextWriter("testSigned.xml", Encoding.UTF8);
            doc.WriteTo(xmltw);
            xmltw.Close();
        }

        [Fact]
        public void VerifyXml()
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load("testSigned.xml");

            var signedXml = new SignedXml(doc);
            XmlNodeList nodeList = doc.GetElementsByTagName("Signature");
            signedXml.LoadXml((XmlElement)nodeList[0]);

            X509Certificate2 cert = null;
            //very basic implementation, don't use as is.
            IEnumerator certInfoList = signedXml.KeyInfo.GetEnumerator(typeof(KeyInfoX509Data));
            while (certInfoList.MoveNext())
            {
                ArrayList certList = ((KeyInfoX509Data)certInfoList.Current).Certificates;
                cert = (X509Certificate2)certList[0];
            }


            publicRsa = cert.GetRSAPublicKey();
            publicEcdsa = cert.GetECDsaPublicKey();
            if (publicRsa != null)
            {
                Assert.True(signedXml.CheckSignature());
            }
            else if (publicEcdsa != null)
            {
                Assert.True(signedXml.CheckSignature(publicEcdsa));
            }
            else
            {
                Assert.True(false);
            }
        }

        [Fact]
        public void WcfClient()
        {
            using (HttpListener listener = new HttpListener())
            {
                listener.Prefixes.Add("http://localhost:6587/");
                listener.Start();
                listener.BeginGetContext(ar =>
                {
                    HttpListenerContext context = listener.EndGetContext(ar);
                    HttpListenerRequest request = context.Request;

                    var inputRead = new StreamReader(request.InputStream, request.ContentEncoding);
                    String inputString = inputRead.ReadToEnd();
                    Debug.WriteLine(inputString);

                    HttpListenerResponse response = context.Response;
                    if (inputString.Contains("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"))
                    {
                        response.StatusCode = 200;
                        response.StatusDescription = "Success - Probably";
                        response.ContentType = "application/soap+xml";
                        response.ContentEncoding = Encoding.UTF8;
                        string responseString = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><EchoResponse xmlns=\"urn:test\"><pong>boe</pong></EchoResponse></s:Body></s:Envelope>";
                        byte[] responseBytes = Encoding.UTF8.GetBytes(responseString);
                        response.ContentLength64 = responseBytes.LongLength;
                        response.OutputStream.Write(responseBytes, 0, responseBytes.Length);
                        response.OutputStream.Close();
                    }
                    else
                    {
                        response.StatusCode = 400;
                        response.StatusDescription = "Failure - For sure";
                    }

                    response.Close();
                }, null);

                
                var binding = new CustomBinding();
                binding.Elements.Add(new CustomSecurityBindingElement());
                binding.Elements.Add(new TextMessageEncodingBindingElement());
                binding.Elements.Add(new HttpTransportBindingElement());

                EndpointAddress ep = new EndpointAddress("http://localhost:6587/MathService/Ep1");
                ChannelFactory<IEcho> channelFactory = new ChannelFactory<IEcho>(binding, ep);
                if (Config.Instance.Thumbprint != null)
                    channelFactory.Credentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, Config.Instance.Thumbprint);
                else
                    channelFactory.Credentials.ClientCertificate.Certificate = Config.Instance.Certificate;

                IEcho client = channelFactory.CreateChannel();

                String pong = client.Echo("boe");
                Assert.Equal("boe", pong);

                listener.Stop();
            }
        }

        public void Dispose()
        {
            eid?.Dispose();
            publicRsa?.Dispose();
            privateRsa?.Dispose();
            publicEcdsa?.Dispose();
            privateEcdsa?.Dispose();
        }

    }

    [ServiceContract(Namespace ="urn:test")]
    interface IEcho
    {
        [OperationContract(Action ="urn:test:ping", ReplyAction = "*")]
        [return: MessageParameter(Name = "pong")]
        string Echo(string ping);
    }
}
