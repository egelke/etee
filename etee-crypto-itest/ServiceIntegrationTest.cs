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
using Siemens.EHealth.Etee.Crypto.Library;
using System.IO;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Etee.ITest
{
    [TestClass]
    public class ServiceIntegrationTest
    {
        /*
         * Different senarios.
         * Care Provider means a known party at eHealth.  Known means a ETK in the ETK-depot.
         */
        private static BasicPostMaster pmForAlice_S_0; //send to addressed Care Provider
        private static BasicPostMaster pmForAlice_SR_0; //send to addressed Care Provider, received addressed message
        private static BasicPostMaster pmForAlice_SR_S; //send to addressed Care Provider, received addressed message, send non-addressed messages
        private static BasicPostMaster pmForAlice_SR_SR; //send to addressed Care Provider, received addressed message, send non-addressed messages, receive non-address messages
        private static BasicPostMaster pmForBob_R_0; //receive addressed messages
        private static BasicPostMaster pmForBob_SR_0; //send to addressed Care Provider, received addressed message
        private static BasicPostMaster pmForBob_SR_SR; //send to addressed Care Provider, received addressed message, send non-addressed messages, receive non-addressed message

        [ClassInitialize]
        public static void InitializeClass(TestContext testContext)
        {


            //Alice, used as sender
            X509Certificate2 alice = new X509Certificate2("users/alice_auth.p12", "test", X509KeyStorageFlags.Exportable);
            X509Certificate2 aliceEnc = new X509Certificate2("users/alice_enc.p12", "test", X509KeyStorageFlags.Exportable);
            //Bob, used as receiver
            X509Certificate2 bob = new X509Certificate2("users/bob_auth.p12", "test", X509KeyStorageFlags.Exportable);
            X509Certificate2 bobEnc = new X509Certificate2("users/bob_enc.p12", "test", X509KeyStorageFlags.Exportable);

            Crypto.Library.ServiceClient.EtkDepotPortTypeClient etkDepot = new Crypto.Library.ServiceClient.EtkDepotPortTypeClient("etk");
            Crypto.Library.ServiceClient.KgssPortTypeClient anonyKgss = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-anon"); //Warning: for Send only!
            Crypto.Library.ServiceClient.KgssPortTypeClient myKgss = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-79021802145"); //Warning: the Kgss port is specific for a person

            //Requires signing-cert (no Encryption cert) + access to ETK-depot
            pmForAlice_S_0 = new BasicPostMaster(SecurityInfo.CreateSendOnly(alice), etkDepot);
            //Requires eHealth-cert + access to ETK-depot
            pmForAlice_SR_0 = new BasicPostMaster(new SecurityInfo(alice, aliceEnc), etkDepot);
            //Requires eHealth-cert + access to ETK-depot + anonymous access to KGSS
            pmForAlice_SR_S = new BasicPostMaster(new SecurityInfo(alice, aliceEnc), etkDepot, anonyKgss);
            //Requires eHealth-cert + access to ETK-depot + authorized access to KGSS
            pmForAlice_SR_SR = new BasicPostMaster(new SecurityInfo(alice, aliceEnc), etkDepot, myKgss);
            //Requires eHealth-cert only
            pmForBob_R_0 = new BasicPostMaster(new SecurityInfo(bob, bobEnc));
            //Requires eHealth-cert + access to ETK-depot
            pmForBob_SR_0 = new BasicPostMaster(new SecurityInfo(bob, bobEnc), etkDepot);
            //Requires eHealth-cert + access to ETK-depot + authorized access to KGSS
            pmForBob_SR_SR = new BasicPostMaster(new SecurityInfo(bob, bobEnc), etkDepot, myKgss);
        }

        [TestCleanup()]
        public void CleanupTest()
        {
            //even disposed it can be reused.
            pmForAlice_S_0.Reset();
            pmForAlice_SR_0.Reset();
            pmForAlice_SR_S.Reset();
            pmForAlice_SR_SR.Reset();
            pmForBob_R_0.Reset();
            pmForBob_SR_0.Reset();
            pmForBob_SR_SR.Reset();
        }

        public void VerifyReceive(Stream msg, X509Certificate2 sender, String orgMsgText)
        {
            //Post Treat
            byte[] msgBytes = new byte[msg.Length];
            msg.Read(msgBytes, 0, msgBytes.Length);
            String msgText = Encoding.UTF8.GetString(msgBytes);


            /*
             * Test Verification
             */
            Assert.AreEqual<String>(orgMsgText, msgText); //check if the text wasn't changed
            Assert.IsTrue(sender.Subject.Contains("00000000101")); //check if it actualy comes from alice
        }

        [TestMethod]
        public void SingleAddressedCapableOfSendingAddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for bob, case 1";

            pmForAlice_S_0.To.Add(pmForBob_R_0);
            pmForAlice_S_0.To.Add(pmForBob_SR_0);
            pmForAlice_S_0.To.Add(pmForBob_SR_SR);

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            KnownRecipient bob = new KnownRecipient("NIHII", "00000000202"); //Create bob, we don't have an ETK.
            recipients.Add(bob); //Add bob as recipient
            pmForAlice_S_0.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Bob (via memory, see BasicPostMaster class)

            //Post treat
            Assert.IsNotNull(bob.Token); //In realy applications save token for future use

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_R_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void SingleAddressedCapableOfAllAddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for bob, case 2";

            pmForAlice_SR_0.To.Add(pmForBob_R_0);
            pmForAlice_SR_0.To.Add(pmForBob_SR_0);
            pmForAlice_SR_0.To.Add(pmForBob_SR_SR);

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            KnownRecipient bob = new KnownRecipient("NIHII", "00000000202"); //Create bob, we don't have an ETK.
            recipients.Add(bob); //Add bob as recipient
            pmForAlice_SR_0.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Bob (via memory, see BasicPostMaster class)

            //Post treat
            Assert.IsNotNull(bob.Token); //In realy applications save token for future use

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_R_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void SingleAddressedCapableOfAllAddressedAndSendingUnaddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for bob, case 3";

            pmForAlice_SR_S.To.Add(pmForBob_R_0);
            pmForAlice_SR_S.To.Add(pmForBob_SR_0);
            pmForAlice_SR_S.To.Add(pmForBob_SR_SR);

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            KnownRecipient bob = new KnownRecipient("NIHII", "00000000202"); //Create bob, we don't have an ETK.
            recipients.Add(bob); //Add bob as recipient
            pmForAlice_SR_S.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Bob (via memory, see BasicPostMaster class)

            //Post treat
            Assert.IsNotNull(bob.Token); //In realy applications save token for future use

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_R_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void SingleAddressedCapableOfAllAddressedAndAllUnaddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for bob, case 4";

            pmForAlice_SR_SR.To.Add(pmForBob_R_0);
            pmForAlice_SR_SR.To.Add(pmForBob_SR_0);
            pmForAlice_SR_SR.To.Add(pmForBob_SR_SR);

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            KnownRecipient bob = new KnownRecipient("NIHII", "00000000202"); //Create bob, we don't have an ETK.
            recipients.Add(bob); //Add bob as recipient
            pmForAlice_SR_SR.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Bob (via memory, see BasicPostMaster class)

            //Post treat
            Assert.IsNotNull(bob.Token); //In realy applications save token for future use

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_R_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void SingleUnaddressedCapableOfSendingUnaddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for group of people, case 1";

            pmForAlice_SR_S.To.Add(pmForBob_SR_SR); //Alice sends to Bob, non-addressed (also supports addressed)

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            recipients.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin", null)); //Any physical person
            pmForAlice_SR_S.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Me (via memory, see BasicPostMaster class)

            //Post treat
            

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void SingleUnaddressedCapableOfAllUnaddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for group of people, case 1";

            pmForAlice_SR_SR.To.Add(pmForBob_SR_SR); //Alice sends to Bob, non-addressed (also supports addressed)

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            recipients.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin", null)); //Any physical person
            pmForAlice_SR_SR.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Me (via memory, see BasicPostMaster class)

            //Post treat


            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void MultiAddressed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for group of people, case 1";

            pmForAlice_SR_S.To.Add(pmForBob_R_0);
            pmForAlice_SR_S.To.Add(pmForBob_SR_0);
            pmForAlice_SR_S.To.Add(pmForBob_SR_SR);

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            KnownRecipient bob = new KnownRecipient("NIHII", "00000000202"); //Create bob, we don't have an ETK.
            recipients.Add(bob); //Add bob as recipient
            KnownRecipient alice = new KnownRecipient("NIHII", "00000000101"); //Create alice, we don't have an ETK.
            recipients.Add(alice); //Add alice as recipient
            pmForAlice_SR_S.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Me (via memory, see BasicPostMaster class)

            //Post treat
            Assert.IsNotNull(bob.Token); //In realy applications save token for future use
            Assert.IsNotNull(alice.Token); //In realy applications save token for future use

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_R_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }

        [TestMethod]
        public void Mixed()
        {
            Stream msg;
            String orgMsgText = "This text should become sealed for group of people, case 1";

            pmForAlice_SR_S.To.Add(pmForBob_R_0); //will receive the addressed
            pmForAlice_SR_S.To.Add(pmForBob_SR_0); //will receive the addressed
            pmForAlice_SR_S.To.Add(pmForBob_SR_SR); //will receive the non-addressed (has priority)
            pmForAlice_SR_S.To.Add(pmForAlice_SR_SR); //will receive the non-addressed

            /*
             * Sender role
             */

            //Prepare
            msg = new MemoryStream(Encoding.UTF8.GetBytes(orgMsgText)); //create a message

            //Send (using library)
            List<Recipient> recipients = new List<Recipient>(); //Define a list of recipients
            KnownRecipient bob = new KnownRecipient("NIHII", "00000000202"); //Create bob, we don't have an ETK.
            recipients.Add(bob); //Add bob as recipient
            recipients.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin", null));
            pmForAlice_SR_S.Send(msg, new ReadOnlyCollection<Recipient>(recipients)); //send message to Me (via memory, see BasicPostMaster class)

            //Post treat
            Assert.IsNotNull(bob.Token); //In realy applications save token for future use

            /*
             * Reciever role
             */

            //Prepare
            X509Certificate2 sender;

            //Receive (using library)
            msg = pmForBob_R_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_0.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForBob_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);

            msg = pmForAlice_SR_SR.Receive(out sender);
            VerifyReceive(msg, sender, orgMsgText);
        }
    }
}
