/*
 * This file is part of .Net ETEE for eHealth.
 * 
 * .Net ETEE for eHealth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * .Net ETEE for eHealth  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Siemens.EHealth.Etee.Crypto.Library;
using System.Collections.ObjectModel;

namespace Siemens.EHealth.Etee.ITest
{
    [TestClass]
    public class RealLifeTest
    {
        private static BasicPostMaster outgoing;
        private static BasicPostMaster incommingSis;
        private static BasicPostMaster incommingSisAsMe;
        private static BasicPostMaster incommingSisByItself;

        [ClassInitialize]
        public static void InitializeClass(TestContext testContext)
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                Crypto.Library.ServiceClient.EtkDepotPortTypeClient etkDepot = new Crypto.Library.ServiceClient.EtkDepotPortTypeClient("etk");
                Crypto.Library.ServiceClient.KgssPortTypeClient kgssForSendOnly = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-anon");
                Crypto.Library.ServiceClient.KgssPortTypeClient kgssForSisAsMe = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-79021802145-0459540270");
                Crypto.Library.ServiceClient.KgssPortTypeClient kgssForSisByItself = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-0459540270");

                X509Certificate2 auth = my.Certificates.Find(X509FindType.FindByThumbprint, "c175242f2454fa00b69b49308f82cae919f8e8f5", true)[0];

                outgoing = new BasicPostMaster(SecurityInfo.Create(auth), etkDepot, kgssForSendOnly);
                incommingSis = new BasicPostMaster(SecurityInfo.Create(auth));
                //incommingSis.Lax = false;
                incommingSisAsMe = new BasicPostMaster(SecurityInfo.Create(auth), etkDepot, kgssForSisAsMe);
                //incommingSis.Lax = false;
                incommingSisByItself = new BasicPostMaster(SecurityInfo.Create(auth), etkDepot, kgssForSisByItself);
                //incommingSisAsMe.Lax = false;
            }
            finally
            {
                my.Close();
            }
        }

        [TestInitialize]
        public void SetupTest()
        {

        }

        [TestCleanup]
        public void CleanupTest()
        {
            outgoing.Reset();
            incommingSis.Reset();
            incommingSisAsMe.Reset();
            incommingSisByItself.Reset();
        }



        [TestMethod]
        public void Send()
        {
            string msg = "My secret message in the name of SIS";
            KnownRecipient self = new KnownRecipient("CBE", "0459540270");
            KnownRecipient eh = new KnownRecipient("SSIN", "78042003561");
            UnknownRecipient anyPers = new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin", null);
            UnknownRecipient anyOrg = new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:kbo-cbe:cbe-number", null);

            List<Recipient> recipients = new List<Recipient>();
            recipients.Add(self);
            recipients.Add(eh);
            recipients.Add(anyOrg);
            recipients.Add(anyPers);

            MemoryStream msgOut = new MemoryStream(Encoding.UTF8.GetBytes(msg));
            outgoing.File = "message_from_sis";
            outgoing.Send(msgOut, new ReadOnlyCollection<Recipient>(recipients));
        }

        [TestMethod]
        public void ReceiveUnknown()
        {
            String msg = "This is a secret message from Eryk for an unknown addressee written at Fri Sep 17 15:09:31 CEST 2010";

            /*
             * Not yet configured
             *
            incommingSisAsMe.Message = new FileStream("message_from_eryk_for_unknown.msg", FileMode.Open);
           
            using (incommingSisAsMe.Message)
            {
                incommingSisAsMe.KeyId = Convert.FromBase64String("vN064UnUgmuhtD9ZBA7d5A==");

                Stream msgIn;
                X509Certificate2 from;

                msgIn = incommingSisAsMe.Receive(out from);
                VerifyReceive(msgIn, from, msg, "78042003561");
            }
            */

            incommingSisByItself.Message = new FileStream("message_from_eryk_for_unknown.msg", FileMode.Open);
            using (incommingSisByItself.Message)
            {
                incommingSisByItself.KeyId = Convert.FromBase64String("vN064UnUgmuhtD9ZBA7d5A==");

                Stream msgIn;
                X509Certificate2 from;

                msgIn = incommingSisByItself.Receive(out from);
                VerifyReceive(msgIn, from, msg, "78042003561");
            }
        }

        [TestMethod]
        public void Receive()
        {
            String msg = "This is a secret message from Eryk for Bryan written at Fri Sep 17 14:01:32 CEST 2010";
            incommingSis.Message = new FileStream("message_from_eryk_for_sis.msg", FileMode.Open);
            using (incommingSis.Message)
            {
                Stream msgIn;
                X509Certificate2 from;

                msgIn = incommingSis.Receive(out from);
                VerifyReceive(msgIn, from, msg, "78042003561");
            }
        }

        public void VerifyReceive(Stream msg, X509Certificate2 sender, String orgMsgText, String user)
        {
            //Post Treat
            byte[] msgBytes = new byte[msg.Length];
            msg.Read(msgBytes, 0, msgBytes.Length);
            String msgText = Encoding.UTF8.GetString(msgBytes);


            /*
             * Test Verification
             */
            Assert.AreEqual<String>(orgMsgText, msgText); //check if the text wasn't changed
            Assert.IsTrue(sender.Subject.Contains(user)); //check if it actualy comes from SIS
        }
    }
}
