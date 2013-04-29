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
    public class ConsultPostMaster : CommonPostMaster
    {


        public ConsultPostMaster(SecurityInfo self, Chap4AgreementConsultationPortTypeClient proxy, EtkDepotPortTypeClient etkDepot, KgssPortTypeClient kgss)
            : base(self, new SecondPassConsultPostMaster(self, proxy, etkDepot), etkDepot, kgss)
        {

        }

        protected override object CreateBusinessRequest(Stream kmehr, byte[] etk)
        {
            Consult.RequestType request = new Consult.RequestType();
            request.EtkHcp = Self.Token.GetEncoded();
            request.KmehrRequest = ReadFully(kmehr);
            return request;
        }

        protected override object CreateIntermediateRequest(Stream encrypted, byte[] keyId, InputParameterData inputParameters)
        {
            Consult.RequestType1 request = new Consult.RequestType1();
            request.CareReceiver = new Consult.CareReceiverIdType();
            request.CareReceiver.Ssin = inputParameters.CareReceiverId.Ssin;
            request.CareReceiver.Mutuality = inputParameters.CareReceiverId.Mutuality;
            request.CareReceiver.RegNrWithMut = inputParameters.CareReceiverId.RegNrWithMut;
            request.AgreementStartDate = inputParameters.AgreementStartDate;
            request.SealedContent = ReadFully(encrypted);
            request.UnsealKeyId = Convert.ToBase64String(keyId);

            return request;
        }

        protected override byte[] ParseResponse(Stream input, out byte[] timestamp)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(Consult.ResponseType));
            Consult.ResponseType responseObject = (Consult.ResponseType)serializer.Deserialize(input);
            timestamp = responseObject.TimestampReply;
            return responseObject.KmehrResponse;
        }

        
    }
}
