using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Egelke.EHealth.Client.EhBox;
using Siemens.EHealth.Etee.Crypto.Library;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using System.Collections.ObjectModel;

namespace Egelke.EHealth.Client.EhBoxTest
{
    [TestClass]
    public class EhBoxExamples
    {
        ehBoxPublicationPortTypeClient publish;

        ehBoxConsultationPortTypeClient consult;

        [TestMethod]
        public void ClearMessageWithConfigViaConfig()
        {
            String msg = "The eH-I library now support publication and consultations of the ehBox";
            publish = new ehBoxPublicationPortTypeClient("Publish");
            consult = new ehBoxConsultationPortTypeClient("Consult");

            var nurse = new PublicationMessageTypeDestinationContext();
            nurse.Id = "83121034221";
            nurse.Type = "INSS";
            nurse.Quality = "NURSE";

            var self = new PublicationMessageTypeDestinationContext();
            self.Id = "0820563481";
            self.Type = "CBE";
            self.Quality = "INSTITUTION";

            CleanupMsgBox();
            String msgId = SendAndCheck(msg, ContentInfoTypeContentType.DOCUMENT, nurse, self);
            String rspMsg = ReceiveMessage(msgId);

            Assert.AreEqual(msg, rspMsg);
        }

        [TestMethod]
        public void EncryptedMsgWithConfigViaConfig()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection found = my.Certificates.Find(X509FindType.FindByThumbprint, "9c4227f1b9c7a52823829837f1a2e80690da8010", false);

            NewsPostMaster pm = new NewsPostMaster(
                SecurityInfo.CreateSendOnly(found[0]), 
                new ehBoxPublicationPortTypeClient("Publish"), 
                new ehBoxConsultationPortTypeClient("Consult"),
                new EtkDepotPortTypeClient("etk"));
            pm.VerifyEtk = false; //better to use it only for testing
            
            List<Recipient> recipients = new List<Recipient>();
            recipients.Add(new EhBoxRecipient("CBE", "0820563481", "INSTITUTION", "MyCareNet"));

            pm.Title = "eH-I supports ehBox";
            String responseId = (String) pm.Send(new MemoryStream(Encoding.UTF8.GetBytes("The eH-I library now support publication of encrypted messages to the ehBox")), new ReadOnlyCollection<Recipient>(recipients));

            Assert.IsFalse(String.IsNullOrWhiteSpace(responseId));
        }

        private void CleanupMsgBox()
        {
            GetMessagesListRequestType selectReq = new GetMessagesListRequestType();
            selectReq.Source = GetMessagesListRequestTypeSource.INBOX;
            GetMessageListResponseType listRsp = consult.getMessagesList(selectReq);

            List<String> msgIds = new List<string>();
            foreach (GetMessageListResponseTypeMessage msg in listRsp.Message)
            {
                msgIds.Add(msg.MessageId);
            }

            MoveMessageRequestType mvReq = new MoveMessageRequestType();
            mvReq.MessageId = msgIds.ToArray();
            mvReq.Source = MoveMessageRequestTypeSource.INBOX;
            mvReq.Destination = MoveMessageRequestTypeDestination.BININBOX;
            Egelke.EHealth.Client.EhBox.ResponseType mvRsp = consult.moveMessage(mvReq);

            Assert.AreEqual("100", mvRsp.Status.Code);
        }

        private String ReceiveMessage(String msgId)
        {
            //check if it exits (not realy needed but demonstrates the usage of the get msg list and it gives us the msg type)
            GetMessagesListRequestType selectReq = new GetMessagesListRequestType();
            selectReq.Source = GetMessagesListRequestTypeSource.INBOX;
            GetMessageListResponseType listRsp = consult.getMessagesList(selectReq);

            Assert.AreEqual("100", listRsp.Status.Code);

            ContentInfoTypeContentType? msgType = null;
            foreach (GetMessageListResponseTypeMessage msg in listRsp.Message)
            {
                if (msg.MessageId == msgId) msgType = msg.ContentInfo.ContentType;
            }

            Assert.IsNotNull(msgType);

            //Now that we know it exists and we know if it news or a document we can move on and get it.
            MessageRequestType fetchReq = new MessageRequestType();
            fetchReq.Source = MessageRequestTypeSource.INBOX;
            fetchReq.MessageId = msgId;

            GetFullMessageResponseType fetchRsp = consult.getFullMessage(fetchReq);

            Assert.AreEqual("100", fetchRsp.Status.Code);

            switch (msgType.Value)
            {
                case ContentInfoTypeContentType.NEWS:
                    NewsType news = (NewsType)fetchRsp.Message.ContentContext.Content.Item;
                    return Encoding.UTF8.GetString(news.Item);
                case ContentInfoTypeContentType.DOCUMENT:
                    DocumentType doc = (DocumentType)fetchRsp.Message.ContentContext.Content.Item;
                    return Encoding.UTF8.GetString(doc.Item);
                default:
                    Assert.Fail();
                    return null;
            }
        }

        private String SendAndCheck(String msg, ContentInfoTypeContentType msgType, params PublicationMessageTypeDestinationContext[] destinations)
        {
            PublicationMessageType publishMessage = new PublicationMessageType();

            //Unique ID to identify the request
            publishMessage.PublicationId = Guid.NewGuid().ToString("N").Substring(18, 13);

            //Indicate your box (optional)
            //publishMessage.BoxId = new BoxIdType();
            //publishMessage.BoxId.Id = "0820563481";
            //publishMessage.BoxId.Type = "CBE";
            //publishMessage.BoxId.Quality = "INSTITUTION";

            //Indicate the box of the destination
            publishMessage.DestinationContext = destinations;

            //And the message we send
            publishMessage.ContentContext = new PublicationMessageTypeContentContext();
            publishMessage.ContentContext.Content = new ContentType();
            switch (msgType)
            {
                case ContentInfoTypeContentType.NEWS:
                    NewsType news = new NewsType();
                    news.Title = "eH-I supports ehBox";
                    news.Item = Encoding.UTF8.GetBytes(msg);
                    news.ItemElementName = ItemChoiceType1.EncryptableTextContent;
                    news.MimeType = "text/plain";
                    publishMessage.ContentContext.Content.Item = news;
                    break;
                case ContentInfoTypeContentType.DOCUMENT:
                    DocumentType doc = new DocumentType();
                    doc.Title = "eH-I supports ehBox";
                    doc.Item = Encoding.UTF8.GetBytes(msg);
                    doc.ItemElementName = ItemChoiceType.EncryptableTextContent;
                    doc.MimeType = "text/plain";
                    doc.DownloadFileName = "msg.txt";
                    publishMessage.ContentContext.Content.Item = doc;
                    break;
            }
            publishMessage.ContentContext.ContentSpecification = new ContentSpecificationType();
            publishMessage.ContentContext.ContentSpecification.IsImportant = false;
            publishMessage.ContentContext.ContentSpecification.IsEncrypted = false;
            publishMessage.ContentContext.ContentSpecification.PublicationReceipt = true;
            publishMessage.ContentContext.ContentSpecification.ReceivedReceipt = true;
            publishMessage.ContentContext.ContentSpecification.ReadReceipt = true;
            publishMessage.ContentContext.ContentSpecification.ApplicationName = "eH-I";

            //Publish the news.
            SendMessageResponse publishResp = publish.sendMessage(publishMessage);

            //check the publish response
            Assert.AreEqual("100", publishResp.Status.Code);

            //Check if the message is received.
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
                Assert.AreEqual("100", ackResp.Status.Code);

                arrived = true;
                //check if all recipients to see if there is one missing
                foreach (GetMessageAcknowledgmentsStatusResponseTypeRow ack in ackResp.AcknowledgmentsStatus)
                {
                    if (!ack.ReceivedSpecified) arrived = false;
                }
            }

            return publishResp.Id;
        }

        private int Fibonacci(int n)
        {
            if (n < 2) return 1;
            return Fibonacci(n - 1) + Fibonacci(n - 2);
        }
    }
}
