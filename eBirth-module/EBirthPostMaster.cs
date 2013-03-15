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

        protected override System.IO.Stream OnTransferFrom(out byte[] keyId)
        {
            keyId = null;
            throw new NotImplementedException();
        }

        protected override void OnTransferTo(System.IO.Stream cyphered, byte[] keyId, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            throw new NotImplementedException();
        }

        protected override void OnTransferTo(System.IO.Stream cyphered, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            byte[] cmsMessage = ReadFully(cyphered);
            Object response = proxy.SendCMSMessage(cmsMessage);
            //TODO: check response...
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
