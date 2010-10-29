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
using Siemens.EHealth.Etee.Crypto.Encrypt;
using Siemens.EHealth.Etee.Crypto;
using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace etee_examples2
{
    public class Seal
    {
        public void MixedByte()
        {
            String msg = "My message";

            //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
            IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);

            //Create a secret key, keyId and Key are retreived from KGSS
            byte[] keyId;
            byte[] key = Utils.GetNewSecretKey(out keyId);
            SecretKey skey = new SecretKey(keyId, key);

            //Read the etk of a specific reciever
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("other.etk"));
            Utils.Check(receiver.Verify()); //verify if it is (still) correct

            //Create a list for the recievers, only one in this case
            List<EncryptionToken> receivers = new List<EncryptionToken>();
            receivers.Add(receiver);

            //Seal a string message, encoded as UTF8.
            byte[] output = sealer.Seal(new ReadOnlyCollection<EncryptionToken>(receivers), Encoding.UTF8.GetBytes(msg), skey);

        }

        public void KnownStream()
        {
            //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
            IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);

            //Read the etk of a specific reciever
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("other.etk"));
            Utils.Check(receiver.Verify()); //verify if it is (still) correct

            //Create a list for the recievers, only one in this case
            List<EncryptionToken> receivers = new List<EncryptionToken>();
            receivers.Add(receiver);

            //Seal as stream
            Stream output;
            FileStream file = new FileStream("text.txt", FileMode.Open);
            using (file)
            {
                output = sealer.Seal(new ReadOnlyCollection<EncryptionToken>(receivers), file);
            }
        }

        public void MixedStream()
        {

            //Create a IDataSealer instance, selfAuth is the eHealth authentication certificate of the user
            IDataSealer sealer = DataSealerFactory.Create(Utils.SelfAuth);

            //Create a secret key, keyId and Key are retreived from KGSS
            byte[] keyId;
            byte[] key = Utils.GetNewSecretKey(out keyId);
            SecretKey skey = new SecretKey(keyId, key);

            //Read the etk of a specific reciever
            EncryptionToken receiver = new EncryptionToken(Utils.ReadFully("other.etk"));
            Utils.Check(receiver.Verify()); //verify if it is (still) correct

            //Create a list for the recievers, only one in this case
            List<EncryptionToken> receivers = new List<EncryptionToken>();
            receivers.Add(receiver);

            //Seal as stream
            Stream output;
            FileStream file = new FileStream("text.txt", FileMode.Open);
            using (file)
            {
                output = sealer.Seal(new ReadOnlyCollection<EncryptionToken>(receivers), file, skey);
            }

        }
    }
}
