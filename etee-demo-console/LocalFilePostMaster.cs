using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.IO;
using System.Collections.ObjectModel;

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

        protected override Tuple<Stream, object> OnTransferEncrypted(Stream encrypted, object parameters, byte[] keyId, ReadOnlyCollection<Recipient> recipients)
        {
            if (encrypted != null)
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
                    encrypted.CopyTo(msg);
                }
                return new Tuple<Stream, object>(null, null);
            }
            else
            {
                if (keyName != null)
                {
                    Stream key = new FileStream(keyName, FileMode.Open);
                    using (key)
                    {
                        keyId = new byte[key.Length];
                        key.Read(keyId, 0, (int)key.Length);
                    }
                }
                else
                {
                    keyId = null;
                }
                return new Tuple<Stream, Object>(new FileStream(msgName, FileMode.Open), null);
            }
        }

    }
}
