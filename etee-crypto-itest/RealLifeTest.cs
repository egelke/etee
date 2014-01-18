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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Library;
using System.Collections.ObjectModel;
using System.Diagnostics;
using NUnit.Framework;

namespace Egelke.EHealth.Etee.ITest
{
    [TestFixture]
    public class RealLifeTest
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Etee");

        X509Certificate2 eid;
        X509Certificate2 rootct2;

        private static PostMaster outgoing;
        private static PostMaster incommingAddressed;
        private static PostMaster incommingUnaddressed;

        FileTransport sharedFileOut;
        FileTransport sharedFileIn;

        [TestFixtureSetUp]
        public void SetUpClass()
        {
            rootct2 = new X509Certificate2("../../rootct2.crt");

            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                if (!store.Certificates.Contains(rootct2))
                {
                    store.Add(rootct2);
                }
            }
            finally
            {
                store.Close();
            }

            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {

                Crypto.Library.ServiceClient.EtkDepotPortTypeClient etkDepot = new Crypto.Library.ServiceClient.EtkDepotPortTypeClient("etk");
                Crypto.Library.ServiceClient.KgssPortTypeClient kgssForSendOnly = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-anon");
                Crypto.Library.ServiceClient.KgssPortTypeClient kgssForMe = new Crypto.Library.ServiceClient.KgssPortTypeClient("kgss-79021802145");

                eid = my.Certificates.Find(X509FindType.FindByThumbprint, "1ac02600f2f2b68f99f1e8eeab2e780470e0ea4c", false)[0];
                X509Certificate2 auth = my.Certificates.Find(X509FindType.FindByThumbprint, "566FD3FE13E3AB185A7224BCEC8AD9CFFBF9E9C2", false)[0];
                X509Certificate2Collection dataEncipherment = my.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DataEncipherment, false);

                X509Certificate2Collection decryption = new X509Certificate2Collection();
                foreach(X509Certificate2 cert in dataEncipherment) {
                    if (cert.HasPrivateKey) decryption.Add(cert);
                }

                sharedFileOut = new OutFileTransport(Path.GetTempFileName(), Path.GetTempFileName());
                sharedFileIn = new InFileTransport(sharedFileOut.Content, sharedFileOut.KekId);

                outgoing = new PostMaster(sharedFileOut, auth, decryption, etkDepot, kgssForSendOnly);
                incommingAddressed = new PostMaster(sharedFileIn, decryption, etkDepot);
                incommingAddressed.Test = true;
                incommingUnaddressed = new PostMaster(sharedFileIn, auth, decryption, etkDepot, kgssForMe);
                incommingUnaddressed.Test = true;
            }
            finally
            {
                my.Close();
            }
        }

        [TestFixtureTearDown]
        public void TearDownClass()
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            try
            {
                if (store.Certificates.Contains(rootct2))
                {
                    store.Remove(rootct2);
                }
            }
            finally
            {
                store.Close();
            }
        }


        [Test]
        public async void Full()
        {
            string msg = "My secret message to myself";


            //sending the message
            Letter outbound = new Letter();
            outbound.Content = new MemoryStream(Encoding.UTF8.GetBytes(msg));
            outbound.Sender = eid;
            outbound.Recipients = new List<Recipient>();
            outbound.Recipients.Add(new KnownRecipient(new KnownRecipient.IdType("SSIN", "79021802145")));
            outbound.Recipients.Add(new UnknownRecipient("urn:be:fgov:identification-namespace", "urn:be:fgov:person:ssin", null));

            await outgoing.TransferAsync(outbound, true, false); //there is not relevant response so we ignore it.

            Letter inbound;

            //getting the message (addressed)
            inbound = await incommingAddressed.TransferAsync(null, false, true);
            using (inbound)
            {
                VerifyReceive(inbound.Content, inbound.Sender, msg, "");
            }
            

            //getting the message (unaddressed)
            inbound = await incommingUnaddressed.TransferAsync(null, false, true);
            using (inbound)
            {
                VerifyReceive(inbound.Content, inbound.Sender, msg, "");
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
            Assert.AreEqual(orgMsgText, msgText); //check if the text wasn't changed
            Assert.IsTrue(sender.Subject.Contains(user)); //check if it actualy comes from SIS
        }
    }
}
