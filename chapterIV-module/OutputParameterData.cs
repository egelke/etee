using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace Egelke.EHealth.Client.ChapterIV
{
    public class OutputParameterData
    {
        private CommonOutputType commonOutput;
        private RecordCommonOutputType recordCommonOutput;
        private X509Certificate2 sender;
        private Stream clearResponse;
        private byte[] timestamp;

        public CommonOutputType CommonOutput
        {
            get { return commonOutput; }
        }

        public RecordCommonOutputType RecordCommonOutput
        {
            get { return recordCommonOutput; }
        }

        internal X509Certificate2 Sender
        {
            get { return sender; }
            set { sender = value; }
        }

        internal Stream ClearResponse
        {
            get { return clearResponse; }
            set { clearResponse = value; }
        }

        public byte[] Timestamp
        {
            get { return timestamp; }
            internal set { timestamp = value; }
        }


        internal OutputParameterData(CommonOutputType commonOutput, RecordCommonOutputType recordCommonOutput)
        {
            this.commonOutput = commonOutput;
            this.recordCommonOutput = recordCommonOutput;
        }
    }
}
