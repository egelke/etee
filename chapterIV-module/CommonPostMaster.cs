using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Serialization;

namespace Egelke.EHealth.Client.ChapterIV
{
    public abstract class CommonPostMaster : PostMaster
    {

        private Collection<UnknownRecipient> ioList;

        private Collection<KnownRecipient> mcnList;

        protected PostMaster innerPostMaster;

        public Collection<UnknownRecipient> IoList
        {
            get { return ioList; }
        }

        public Collection<KnownRecipient> McnList
        {
            get { return mcnList; }
        }


        public CommonPostMaster(SecurityInfo self, PostMaster innerPostMaster, EtkDepotPortTypeClient etkDepot, KgssPortTypeClient kgss)
            : base(self, etkDepot, kgss)
        {
            if (self == null) throw new ArgumentNullException("self");
            if (self.IsSendOnly) throw new ArgumentException("The self argument must be able to receive", "self");
            if (self.Token == null) throw new ArgumentException("The self argument must have a ETK", "self");
            if (etkDepot == null) throw new ArgumentNullException("etkDepot");
            if (kgss == null) throw new ArgumentNullException("kgss");

            this.innerPostMaster = innerPostMaster;

            mcnList = new Collection<KnownRecipient>();
            mcnList.Add(new KnownRecipient("CBE", "0820563481", "MYCARENET"));

            ioList = new Collection<UnknownRecipient>();
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0411702543")); //100
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0411709768")); //200
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0411724220")); //300
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0411729366")); //400
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0411766483")); //500
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0206732437")); //600
            ioList.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", "0250871001")); //900
        }

        /// <summary>
        /// Communicates with the Chapter IV agreement consult service.
        /// </summary>
        /// <param name="kmehr">The request kmehr, that must be double encrypted</param>
        /// <param name="parameters">Additional information required, see Chapter IV documentation</param>
        /// <param name="sender">The certificate of the IO that sent the response</param>
        /// <returns>The response kmehr (item1) and additional information (item2)</returns>
        /// <exception cref="AgreementException">When the service returns a fault in the business message</exception>
        public Tuple<Stream, OutputParameterData> Transfer(Stream kmehr, InputParameterData parameters, out X509Certificate2 sender)
        {
            //Create the request with the KMEHR
            Object request = CreateBusinessRequest(kmehr, Self.Token.GetEncoded());

            //Encrypte request and send, the response isn't encrypted on this level (but is on the second pass)
            Object response = TransferAndEncryptOnly(SerializeInMemory(request), (Object)parameters, new ReadOnlyCollection<Recipient>(ioList.ToList<Recipient>()));

            //Convert the response
            OutputParameterData responseParameter = (OutputParameterData)response;

            //Get the sender and remove it from teh response parameter
            sender = responseParameter.Sender;
            responseParameter.Sender = null;

            //desialize the response
            byte[] timestamp;
            byte[] kmehrResponse = ParseResponse(responseParameter.ClearResponse, out timestamp);
            
            //clear the (internal) input and return the response
            responseParameter.ClearResponse = null;
            responseParameter.Timestamp = timestamp;
            return new Tuple<Stream,OutputParameterData>(new MemoryStream(kmehrResponse), responseParameter);
        }

        protected abstract Object CreateBusinessRequest(Stream kmehr, byte[] etk);

        protected abstract Object CreateIntermediateRequest(Stream encrypted, byte[] keyId, InputParameterData inputParameters);

        protected abstract byte[] ParseResponse(Stream input, out byte[] timestamp);

        protected override Tuple<Stream, object> OnTransferEncrypted(Stream encrypted, Object parameters, ref byte[] keyId, ReadOnlyCollection<Recipient> recipients)
        {
            if (!(parameters is InputParameterData)) throw new ArgumentException("The parameters agrument must be a input parameter data", "parameters");
            InputParameterData inputParameters = (InputParameterData) parameters;

            //Create a new request, containing the unaddressed encrypted content.
            Object request = CreateIntermediateRequest(encrypted, keyId, inputParameters);
            
            X509Certificate2 sender;
            //send via the inner postmaster
            Tuple<Stream, Object> response = innerPostMaster.TransferAndDoCrypto(SerializeInMemory(request), parameters, new ReadOnlyCollection<Recipient>(mcnList.ToList<Recipient>()), out sender);

            //Prepare a new tuple with all the clear data (including the stream, since at this point it is clear data)
            OutputParameterData responseParameter = (OutputParameterData)response.Item2;
            responseParameter.ClearResponse = response.Item1;
            responseParameter.Sender = sender;

            return new Tuple<Stream, Object>(null, responseParameter); //stream nust be null, otherwise the postmaster will try to decrypt it.
        }

        private static MemoryStream SerializeInMemory(Object request)
        {
            MemoryStream requestStream = new MemoryStream();
            XmlSerializer serializer = new XmlSerializer(request.GetType());
            serializer.Serialize(requestStream, request);
            requestStream.Seek(0, SeekOrigin.Begin);
            return requestStream;
        }

        protected static byte[] ReadFully(Stream input)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                input.CopyTo(ms);
                return ms.ToArray();
            }
        }
    }
}
