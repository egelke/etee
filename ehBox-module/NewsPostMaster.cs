using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;

namespace Egelke.EHealth.Client.EhBox
{
    public class NewsPostMaster : PostMaster
    {

        private String title;

        private String application = "eH-I";

        private bool important = false;

        private bool publicationReceipt = false;

        private bool receivedReceipt = false;

        private bool readReceipt = false;

        private ehBoxPublicationPortTypeClient publish;

        private ehBoxConsultationPortTypeClient consult;

        public String Title
        {
            get
            {
                return title;
            }
            set
            {
                title = value;
            }
        }

        public NewsPostMaster(SecurityInfo self, ehBoxPublicationPortTypeClient publish, ehBoxConsultationPortTypeClient consult)
            : base(self)
        {
            this.publish = publish;
            this.consult = consult;
        }

        public NewsPostMaster(SecurityInfo self, ehBoxPublicationPortTypeClient publish, ehBoxConsultationPortTypeClient consult, EtkDepotPortTypeClient etkDepot)
            : base(self, etkDepot)
        {
            this.publish = publish;
            this.consult = consult;
        }

        protected override Tuple<Stream, object> OnTransferEncrypted(Stream encrypted, object parameters, ref byte[] keyId, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            PublicationMessageType publishMessage = new PublicationMessageType();

            //Request the ehBox to deliver the message to the ehBox recipients.
            publishMessage.PublicationId = Guid.NewGuid().ToString("N").Substring(18, 13);
            List<PublicationMessageTypeDestinationContext> recipientAddresses = new List<PublicationMessageTypeDestinationContext>();
            for (int i = 0; i < recipients.Count; i++)
            {
                EhBoxRecipient recipient = recipients[i] as EhBoxRecipient;
                if (recipient == null) continue; //we only send it to the known recipients

                PublicationMessageTypeDestinationContext address = new PublicationMessageTypeDestinationContext();
                address.Id = recipient.Id;
                address.Type = recipient.Type;
                address.Quality = recipient.Quality;

                recipientAddresses.Add(address);
            }
            if (recipientAddresses.Count == 0) throw new ArgumentException("At least one recipient must be an eHBox recipient", "recipients");
            publishMessage.DestinationContext = recipientAddresses.ToArray();

            //The news.
            publishMessage.ContentContext = new PublicationMessageTypeContentContext();
            publishMessage.ContentContext.Content = new ContentType();

            NewsType news = new NewsType();
            news.Title = this.title;
            news.Item = ReadFully(encrypted);
            news.ItemElementName = ItemChoiceType1.EncryptableTextContent;
            news.MimeType = "text/plain";
            publishMessage.ContentContext.Content.Item = news;

            //New specifications
            publishMessage.ContentContext.ContentSpecification = new ContentSpecificationType();
            publishMessage.ContentContext.ContentSpecification.IsImportant = important;
            publishMessage.ContentContext.ContentSpecification.IsEncrypted = true;
            publishMessage.ContentContext.ContentSpecification.PublicationReceipt = publicationReceipt;
            publishMessage.ContentContext.ContentSpecification.ReceivedReceipt = receivedReceipt;
            publishMessage.ContentContext.ContentSpecification.ReadReceipt = readReceipt;
            publishMessage.ContentContext.ContentSpecification.ApplicationName = application;

            //Publish the news.
            SendMessageResponse publishResp = publish.sendMessage(publishMessage);

            //check the publish response
            if ("100" != publishResp.Status.Code)
            {
                throw new InvalidOperationException("publish to the ehBox failed");
            }

            if (publicationReceipt || receivedReceipt)
            {
                //TODO:make async

                //Check if the message is published/received.
                GetMessageAcknowledgmentsStatusRequestType ackReq = new GetMessageAcknowledgmentsStatusRequestType();
                ackReq.MessageId = publishResp.Id;
                ackReq.StartIndex = 1;
                ackReq.EndIndex = 100;

                //Loop until the new is received.
                int loop = 0;
                bool arrived = false;
                while (loop < 8 && !arrived)
                {
                    //Give eHealth some time (each time a little more)
                    System.Threading.Thread.Sleep(new TimeSpan(0, 0, Fibonacci(loop++)));

                    //Get the status
                    GetMessageAcknowledgmentsStatusResponseType ackResp = consult.getMessageAcknowledgmentsStatus(ackReq);

                    //check the publish response
                    if ("100" != publishResp.Status.Code)
                    {
                        throw new InvalidOperationException("publish to the ehBox succeeded, but can't retreive receipt");
                    }

                    arrived = true;
                    //check if all recipients to see if there is one missing
                    foreach (GetMessageAcknowledgmentsStatusResponseTypeRow ack in ackResp.AcknowledgmentsStatus)
                    {
                        if (receivedReceipt)
                        {
                            if (!ack.ReceivedSpecified) arrived = false;
                        }
                        else
                        {
                            if (!ack.PublishedSpecified) arrived = false;
                        }
                    }
                }
                if (!arrived)
                {
                    if (receivedReceipt)
                    {
                        throw new InvalidOperationException("publish to the ehBox succeeded, but not received");
                    }
                    else
                    {
                        throw new InvalidOperationException("publish to the ehBox succeeded, but not published");
                    }
                }
            }

            //TODO: also also Receipts info.
            return new Tuple<Stream,object>(null, publishResp.Id);
        }

        private static int Fibonacci(int n)
        {
            if (n < 2) return 1;
            return Fibonacci(n - 1) + Fibonacci(n - 2);
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
