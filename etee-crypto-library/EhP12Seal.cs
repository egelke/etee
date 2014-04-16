using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Sender;
using System;
using System.Activities;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Egelke.EHealth.Etee.Crypto.Wf
{
    public class EhP12Seal : CodeActivity
    {
        private const String KnownRecipientRx = "(?<type>.*)=(?<value>\\d*)(, (?<app>\\w+))?";

        public InArgument<Level> Level;

        public InArgument<String> P12File;

        public InArgument<String> P12Password;

        public InArgument<TimeInfoType> TimeInfoType;

        public InArgument<String> TimeInfoUrl;

        public InArgument<String> EtkDepotUrl;

        public InArgument<Stream> InMsg;

        public InArgument<String[]> KnownRecipients;

        //public InArgument<byte[]> UnknownRecipients;

        public OutArgument<Stream> OutMsg;

        protected override void Execute(CodeActivityContext context)
        {
            String p12File = P12File.Get(context);
            String p12Pwd = P12Password.Get(context);
            EHealthP12 p12 = new EHealthP12(p12File, p12Pwd);

            IDataSealer sealer;
            Level level = Level.Get(context);
            switch (level)
            {
                case Crypto.Level.B_Level:
                    sealer = EhDataSealerFactory.Create(level, p12);
                    break;
                case Crypto.Level.L_Level:
                case Crypto.Level.LT_Level:
                case Crypto.Level.LTA_Level:
                    TimeInfoType timeInfo = TimeInfoType.Get(context);
                    switch (timeInfo)
                    {
                        case Wf.TimeInfoType.TimeMarkAuthority:
                            sealer = EhDataSealerFactory.CreateForTimemarkAuthority(level, p12);
                            break;
                        case Wf.TimeInfoType.TimeStampAuthrity_Rfc3161:
                            String tsaUrl = TimeInfoUrl.Get(context);
                            sealer = EhDataSealerFactory.Create(level, new Rfc3161TimestampProvider(new Uri(tsaUrl)), p12);
                            break;
                        default:
                            throw new NotImplementedException();
                    }
                    break;
                default:
                    throw new ArgumentException("Level", "Only levels B, T, LT and LTA are allowed");
            }

            String[] knownRecipients = KnownRecipients.Get(context);
            if (knownRecipients != null && knownRecipients.Length > 0) {
                Regex knownRecipientRegex = new Regex(KnownRecipientRx);
                ServiceClient.EtkDepotPortTypeClient etkDepotClient = new ServiceClient.EtkDepotPortTypeClient(new BasicHttpBinding(), new EndpointAddress(EtkDepotUrl.Get(context)));
                ServiceClient.GetEtkRequest request = new ServiceClient.GetEtkRequest();
                request.SearchCriteria = new ServiceClient.IdentifierType[knownRecipients.Length];
                for(int i=0; i<knownRecipients.Length; i++) {
                    MatchCollection matches = knownRecipientRegex.Matches(knownRecipients[0]);

                    request.SearchCriteria[0] = new ServiceClient.IdentifierType();
                    request.SearchCriteria[0].Type = matches[0].Groups["type"].Value;
                    request.SearchCriteria[0].Value = matches[0].Groups["value"].Value;
                    request.SearchCriteria[0].ApplicationID = matches[0].Groups["app"].Success ? matches[0].Groups["app"].Value : null;
                }

                etkDepotClient.GetEtk(request);
            }


            sealer.Seal(InMsg.Get(context), null, )
        }
    }
}
