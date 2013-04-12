using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using System.Collections.ObjectModel;
using System.ServiceModel;

namespace Egelke.EHealth.Client.ChapterIV
{
    internal class SecondPassConsultPostMaster : PostMaster
    {
        private Chap4AgreementConsultationPortTypeClient proxy;

        public SecondPassConsultPostMaster(SecurityInfo self, Chap4AgreementConsultationPortTypeClient proxy, EtkDepotPortTypeClient etkDepot)
            : base(self, etkDepot)
        {
            this.proxy = proxy;
        }

        protected override Tuple<Stream, Object> OnTransferEncrypted(Stream encrypted, Object parameters, ref byte[] keyId, ReadOnlyCollection<Recipient> recipients)
        {
            InputParameterData inputParameters = (InputParameterData) parameters;

            //construct the request from parameters and the encrypted message
            ConsultChap4MedicalAdvisorAgreementRequestType request = new ConsultChap4MedicalAdvisorAgreementRequestType();
            request.CommonInput = inputParameters.CommonInput;
            request.RecordCommonInput = inputParameters.RecordCommonInput;
            request.CareReceiver = inputParameters.CareReceiverId;
            request.Request = new SecuredContentType();
            request.Request.SecuredContent = ReadFully(encrypted);

            //Send the request and get the response.
            ConsultChap4MedicalAdvisorAgreementResponseType response;
            try
            {
                response = proxy.consultChap4MedicalAdvisorAgreement(request);
            }
            catch (FaultException<SystemError> systemError)
            {
                String code = systemError.Detail.Nodes.Where(x => x.LocalName == "Code").Single().InnerText;
                String msg = systemError.Detail.Nodes.Where(x => x.LocalName == "Message").Single().InnerText;
                String id = systemError.Detail.Nodes.Where(x => x.LocalName == "Id").Single().InnerText;
                throw new InvalidOperationException(code + ": " + msg + " (" + id + ")");
            }

            //Verify the response for errors, return an exception if found.
            if (response.Status.Code != "200" || response.ReturnInfo != null)
            {
                throw new AgreementException(response.Status, response.ReturnInfo, response.CommonOutput, response.RecordCommonOutput);
            }

            //Extract the non encrypted data and the encrypted steam
            OutputParameterData outputParameters = new OutputParameterData(response.CommonOutput, response.RecordCommonOutput);
            return new Tuple<Stream, Object>(new MemoryStream(response.Response.SecuredContent), outputParameters);
        }

        private static byte[] ReadFully(Stream input)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                input.CopyTo(ms);
                return ms.ToArray();
            }
        }
    }
}
