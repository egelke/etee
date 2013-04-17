using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Etee.Crypto.Library;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using System.Collections.ObjectModel;
using Egelke.EHealth.Client.EBirth;

namespace Egelke.EHealth.Client.EBirthTest
{
    [TestClass]
    public class EBirthExamples
    {
        [TestMethod]
        public void EncryptedMsgWithConfigViaConfig()
        {
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection found = my.Certificates.Find(X509FindType.FindByThumbprint, "9c4227f1b9c7a52823829837f1a2e80690da8010", false);

            EBirthPostMaster pm = new EBirthPostMaster(
                SecurityInfo.CreateSendOnly(found[0]),
                new TTPPortTypeClient("notification"), 
                new EtkDepotPortTypeClient("etk"));
            pm.VerifyEtk = false; //better to use it only for testing
            
            List<Recipient> recipients = new List<Recipient>();
            recipients.Add(new KnownRecipient("CBE", "0367302178", "EBIRTHTEST"));

            Object response = pm.TransferAndEncryptOnly(new FileStream("notification_kmehr.xml", FileMode.Open, FileAccess.Read), null, new ReadOnlyCollection<Recipient>(recipients));
        }
    }
}
