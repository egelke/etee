using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;

namespace Siemens.EHealth.Etee.Demo.Console
{
    class LocalFilePostMaster : PostMaster
    {

        private string msgName;
        private string keyName;

        public string MsgName
        {
            get
            {
                return msgName;
            }
            set
            {
                msgName = value;
            }
        }

        public string KeyName
        {
            get
            {
                return keyName;
            }
            set
            {
                keyName = value;
            }
        }

        public LocalFilePostMaster(SecurityInfo self)
            : base(self)
        {

        }

        public LocalFilePostMaster(SecurityInfo self, EtkDepotPortTypeClient etkDepot)
            : base(self, etkDepot)
        {

        }

        public LocalFilePostMaster(SecurityInfo self, EtkDepotPortTypeClient etkDepot, KgssPortTypeClient kgss)
            : base(self, etkDepot, kgss)
        {

        }

        protected override System.IO.Stream OnTransferFrom(Object parameters, out byte[] keyId)
        {
            if (keyName != null)
            {

                Stream key = new FileStream(keyName, FileMode.Open);
                using (key)
                {
                    keyId = new byte[key.Length];
                    key.Read(keyId, 0, (int) key.Length);
                }
            }
            else
            {
                keyId = null;
            }
            return new FileStream(msgName, FileMode.Open);
        }

        protected override Object OnTransferTo(System.IO.Stream cyphered, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            return OnTransferTo(cyphered, null, recipients);
        }

        protected override Object OnTransferTo(System.IO.Stream cyphered, byte[] keyId, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            if (keyId != null)
            {
                FileStream key = new FileStream(keyName, FileMode.Create);
                using (key)
                {
                    key.Write(keyId, 0, keyId.Length);
                }
            }
            FileStream msg = new FileStream(msgName, FileMode.Create);
            using (msg)
            {
                int read;
                byte[] buffer = new byte[1024];
                while ( (read = cyphered.Read(buffer, 0, buffer.Length)) > 0)
                {
                    msg.Write(buffer, 0, read);
                }
            }
            return null;
        }
    }
}
