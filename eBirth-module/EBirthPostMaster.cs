using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;

namespace Egelke.EHealth.Client.EBirth
{
    public class EBirthPostMaster : PostMaster
    {

        private TTPPortTypeClient proxy;

        public EBirthPostMaster(SecurityInfo self, TTPPortTypeClient proxy)
            : base(self)
        {
            this.proxy = proxy;
        }

        public EBirthPostMaster(SecurityInfo self, TTPPortTypeClient proxy, EtkDepotPortTypeClient etkDepot)
            : base(self, etkDepot)
        {
            this.proxy = proxy;
        }

        protected override Tuple<Stream, object> OnTransferEncrypted(Stream encrypted, object parameters, ref byte[] keyId, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            byte[] cmsMessage = ReadFully(encrypted);
            Object response = proxy.SendCMSMessage(cmsMessage);
            //TODO: check response...

            return new Tuple<Stream, Object>(null, response);
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
