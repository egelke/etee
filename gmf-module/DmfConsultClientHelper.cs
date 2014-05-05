using Egelke.EHealth.Client.Gmf.Msg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace Egelke.EHealth.Client.Gmf
{
    public static class DmfConsultClientHelper
    {


        public static ConsultResponse Consult(this GlobalMedicalFileConsultationPortTypeClient client, CommonInputType common, RoutingType routing, RetrieveTransactionRequestType detailValue, out ArchivingInfo archivingInfo)
        {
            var detail = new BlobType();
            detail.Id = "_" + Guid.NewGuid().ToString();
            detail.ContentType = "text/xml";
            detail.ContentEncoding = "none";
            var detailStream = new MemoryStream();
            var serializer = new XmlSerializer(typeof(RetrieveTransactionRequestType));
            serializer.Serialize(detailStream, detailValue);
            detail.Value = detailStream.ToArray();

            ResponseReturnType super = client.Consult(common, routing, detail);

            archivingInfo = new ArchivingInfo();
            archivingInfo.RequestDetail = detail;
            archivingInfo.RequestXadesT = null;
            archivingInfo.ResponseDetail = super.Detail;
            archivingInfo.ResponseXadesT = super.XadesT;

            var retVal = new ConsultResponse();
            retVal.Common = super.CommonOutput;
            if (super.Detail.ContentType == "text/xml"
                && super.Detail.ContentEncoding == "none")
            {
                var reader = XmlReader.Create(new MemoryStream(super.Detail.Value));
                var deserializer = new XmlSerializer(typeof(RetrieveTransactionResponseType));
                if (deserializer.CanDeserialize(reader))
                {
                    retVal.DetailValue = deserializer.Deserialize(reader) as RetrieveTransactionResponseType;
                }
            }

            return retVal;
        }

        public static ResponseReturnType Consult(this GlobalMedicalFileConsultationPortTypeClient client, CommonInputType common, RoutingType routing, BlobType detail)
        {
            SendRequestType request = new SendRequestType();
            request.CommonInput = common;
            request.Routing = routing;
            request.Detail = detail;
            //No xades required

            SendResponseType response = client.consultGlobalMedicalFile(request);
            if (response.Status.Code != "200") throw new InvalidOperationException(String.Format("eHealth returned the following status: {0}, {1}", response.Status.Code, response.Status.Message[0].Value));

            //No xades returned

            return response.Return;
        }
    }
}
