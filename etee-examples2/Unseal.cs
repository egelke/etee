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
using Siemens.EHealth.Etee.Crypto.Decrypt;
using System.IO;
using Siemens.EHealth.Etee.Crypto;

namespace etee_examples2
{
    class Unseal
    {

        public void Known()
        {
            //Create a IDataSealer instance
            IDataUnsealer unsealer = DataUnsealerFactory.Create(Utils.SelfEnc, Utils.SelfAuth);

            UnsealResult result;
            FileStream file = new FileStream("protectedForMe.msg", FileMode.Open);
            using (file)
            {
                result = unsealer.Unseal(file);
            }
            //Check if the content is in order
            if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid) throw new Exception(result.SecurityInformation.ToString());
            //Check if sender and receiver used valid and up to spec certificates
            if (result.SecurityInformation.TrustStatus != TrustStatus.Full) throw new Exception(result.SecurityInformation.ToString());
            //Check if the sender is allowed to send a message (application specific)
            VerifySender(result.Sender);
            //Use the message (application specific)
            ImportMessage(result.UnsealedData);
        }

        public void Unknown()
        {
            //Create a IAnonymousDataSealer instance
            IAnonymousDataUnsealer unsealer = DataUnsealerFactory.Create();
             
            //Read the key id send by the sender
            byte[] keyId = Utils.ReadFully("protectedForGroup.kid");
            //Get the key from the KGSS
            byte[] key = GetKeyFromKGSS(keyId);
            //Create a secrte key object
            SecretKey skey = new SecretKey(keyId, key);
             
            UnsealResult result;
            FileStream file = new FileStream("protectedForGroup.msg", FileMode.Open);
            using(file)
            {
                 result = unsealer.Unseal(file, skey);
             }
             //Check if the content is in order
             if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid) throw new Exception(result.SecurityInformation.ToString());
             //Check if sender and receiver used valid and up to spec certificates
             if (result.SecurityInformation.TrustStatus != TrustStatus.Full) throw new Exception(result.SecurityInformation.ToString());
             //Check if the sender is allowed to send a message (application specific)
             VerifySender(result.Sender);
             //Use the message (application specific)
             ImportMessage(result.UnsealedData);
        }

        private byte[] GetKeyFromKGSS(byte[] keyId)
        {
            throw new NotImplementedException();
        }

        private void ImportMessage(Stream stream)
        {
            throw new NotImplementedException();
        }

        private void VerifySender(System.Security.Cryptography.X509Certificates.X509Certificate2 x509Certificate2)
        {
            throw new NotImplementedException();
        }

     
    }
}
