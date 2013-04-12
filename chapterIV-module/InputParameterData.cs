using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Client.ChapterIV
{
    public class InputParameterData
    {
        public CommonInputType CommonInput { get; set; }
        public RecordCommonInputType RecordCommonInput { get; set; }
        public CareReceiverIdType CareReceiverId { get;set; }
        public DateTime AgreementStartDate { get;set; }

        public InputParameterData()
        {

        }

        public InputParameterData(CommonInputType commonInput, RecordCommonInputType recordCommonInput, CareReceiverIdType careReceiverId, DateTime agreementStartDate)
        {
            this.CommonInput = commonInput;
            this.RecordCommonInput = recordCommonInput;
            this.CareReceiverId = careReceiverId;
            this.AgreementStartDate = agreementStartDate;
        }
                
    }
}
