using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Egelke.EHealth.Client.ChapterIV
{
    public class AgreementException : Exception
    {
        private StatusType status;

        private FaultType fault;

        private CommonOutputType commonOutput;

        private RecordCommonOutputType recordCommonOutput;

        public StatusType Status
        {
            get { return status; }
        }

        public FaultType Fault
        {
            get { return fault; }
        }

        public CommonOutputType CommonOutput
        {
            get { return commonOutput; }
        }

        public RecordCommonOutputType RecordCommonOutput
        {
            get { return recordCommonOutput; }
        }

        public AgreementException(StatusType status, FaultType fault, CommonOutputType commonOutput, RecordCommonOutputType recordCommonOutput)
            : base(status.Code == "200" ? fault.Message.Value : status.Message.Where(x => x.LangSpecified && x.Lang == LangageType.EN).Single().Value)
        {
            this.status = status;
            this.fault = fault;
            this.commonOutput = commonOutput;
            this.recordCommonOutput = recordCommonOutput;
        }
    }
}
