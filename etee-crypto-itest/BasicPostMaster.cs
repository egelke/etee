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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Siemens.EHealth.Etee.Crypto.Library;
using System.IO;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;

namespace Siemens.EHealth.Etee.ITest
{
    /// <summary>
    /// PostMaster implementation that transfer it directly to another Postmaster object in memory.
    /// </summary>
    class BasicPostMaster : PostMaster
    {
        private String file;

        private Stream msg;

        private byte[] keyId;

        private byte[] key;

        private List<BasicPostMaster> to = new List<BasicPostMaster>();

        /// <summary>
        /// Postmaster to send message to, only used for Send.
        /// </summary>
        public List<BasicPostMaster> To
        {
            get { return to; }
        }


        public String File
        {
            get
            {
                return file;
            }
            set
            {
                file = value;
            }
        }

        public Stream Message
        {
            get
            {
                return msg;
            }
            set
            {
                msg = value;
            }
        }

        public byte[] KeyId
        {
            get
            {
                return keyId;
            }
            set
            {
                keyId = value;
            }
        }

        public byte[] Key
        {
            get
            {
                return key;
            }
            set
            {
                key = value;
            }
        }


        public BasicPostMaster(SecurityInfo self)
            : base(self)
        {

        }

        public BasicPostMaster(SecurityInfo self, EtkDepotPortTypeClient etkDepot)
            : base(self, etkDepot)
        {

        }

        public BasicPostMaster(SecurityInfo self, EtkDepotPortTypeClient etkDepot, KgssPortTypeClient kgss)
            : base(self, etkDepot, kgss)
        {

        }


        protected override System.IO.Stream OnTransferFrom(out byte[] keyId)
        {
            keyId = this.keyId;
            return this.msg;
        }

        protected override void OnTransferTo(System.IO.Stream cyphered, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            if (!String.IsNullOrWhiteSpace(file))
            {
                FileStream fs = new FileStream(file + ".msg", FileMode.Create);
                using (fs)
                {
                    Utils.Copy(cyphered, fs);
                }
            }
            foreach (BasicPostMaster pm in to)
            {
                pm.msg = new MemoryStream();
                Utils.Copy(cyphered, pm.msg);
                pm.keyId = null;
            }
        }

        protected override void OnTransferTo(System.IO.Stream cyphered, byte[] keyId, System.Collections.ObjectModel.ReadOnlyCollection<Recipient> recipients)
        {
            if (!String.IsNullOrWhiteSpace(file))
            {
                FileStream fs = new FileStream(file + ".msg", FileMode.Create);
                using (fs)
                {
                    Utils.Copy(cyphered, fs);
                }
                fs = new FileStream(file + ".key", FileMode.Create);
                using (fs)
                {
                    fs.Write(keyId, 0, keyId.Length);
                }
            }
            foreach (BasicPostMaster pm in to)
            {
                pm.msg = new MemoryStream();
                Utils.Copy(cyphered, pm.msg);
                pm.keyId = keyId;
            }
        }

        protected override Crypto.SecretKey GetKek(byte[] keyId)
        {
            if (key == null)
            {
                return base.GetKek(keyId);
            }
            else
            {
                return new Crypto.SecretKey(keyId, key);
            }
        }

        public void Reset()
        {
            this.to.Clear();
            this.keyId = null;
            this.key = null;
            this.msg = null;
        }

    }
}
