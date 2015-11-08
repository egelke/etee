/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
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
using System.ServiceModel;
using Egelke.EHealth.Client.Sso.Sts;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Description;
using Egelke.EHealth.Client.Sso.WA;
using Siemens.EHealth.Client.Codage;



namespace Siemens.EHealth.Client.CodageTest
{
    [TestClass]
    public class Examples
    {
        [TestMethod]
        public void ConfigViaCode()
        {
            //create service stub
            CodageClient client = new CodageClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be:443/codage_1_0/codage"));
            client.Endpoint.Behaviors.Remove<ClientCredentials>();
            client.Endpoint.Behaviors.Add(new OptClientCredentials());
            client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c6c3cba1000c955c2e6289c6eb40bbb7477476c0");

            DoTest(client);
        }

        [TestMethod]
        public void ConfigViaConfig()
        {
            CodageClient client = new CodageClient("Ssin");

            DoTest(client);
        }

        private static void DoTest(CodageClient client)
        {
            //Do encoding
            OriginalDataType org1 = new OriginalDataType();
            org1.randomize = false;
            org1.id = "1";
            org1.inputData = "79021802145";

            OriginalDataType org2 = new OriginalDataType();
            org2.randomize = true;
            org2.id = "2";
            org2.inputData = "0459540270";

            EncodeRequestType encReq = new EncodeRequestType();
            encReq.applicationName = "Test";
            encReq.originalData = new OriginalDataType[] { org1, org2 };

            EncodeResponseType encResp = client.Encode(encReq);

            //Verify encoding result
            Assert.IsFalse(string.IsNullOrWhiteSpace(encResp.ticketNumber));
            if (encResp.globalError != null) Assert.Fail(encResp.globalError.errorValue);
            Assert.AreEqual(encReq.applicationName, encResp.applicationName);

            IEnumerable<ErrorType> encErrors = from r in encResp.response where r.error != null select r.error;
            Assert.Equals(0, encErrors.Count());
            //Here you normaly check the errors, but since it is only a test it fails right here

            EncodedDataType encDetail1 = (from r in encResp.response where r.encodedData != null && r.encodedData.id == "1" select r.encodedData).Single();
            Assert.IsNotNull(encDetail1.value);
            Assert.AreNotEqual(0, encDetail1.value.Length);

            EncodedDataType encDetail2 = (from r in encResp.response where r.encodedData != null && r.encodedData.id == "2" select r.encodedData).Single();
            Assert.IsNotNull(encDetail2.value);
            Assert.AreNotEqual(0, encDetail2.value.Length);

            //Do decoding
            EncodedDataType enc1 = new EncodedDataType();
            enc1.id = "1";
            enc1.value = encDetail1.value;

            EncodedDataType enc2 = new EncodedDataType();
            enc2.id = "2";
            enc2.value = encDetail2.value;

            DecodeRequestType decReq = new DecodeRequestType();
            decReq.applicationName = "Test";
            decReq.encodedData = new EncodedDataType[] { enc1, enc2 };

            DecodeResponseType decResp = client.Decode(decReq);
            Assert.IsFalse(string.IsNullOrWhiteSpace(decResp.ticketNumber));
            if (decResp.globalError != null) Assert.Fail(decResp.globalError.errorValue);

            IEnumerable<ErrorType> decErrors = from r in decResp.response where r.error != null select r.error;
            Assert.AreEqual(0, decErrors.Count());
            //Here you normaly check the errors, but since it is only a test it fails right here

            DecodedDataType decDetail1 = (from r in decResp.response where r.decodedData != null && r.decodedData.id == "1" select r.decodedData).Single();
            Assert.AreEqual(org1.inputData, decDetail1.outputData);

            DecodedDataType decDetail2 = (from r in decResp.response where r.decodedData != null && r.decodedData.id == "2" select r.decodedData).Single();
            Assert.AreEqual(org2.inputData, decDetail2.outputData);
        }
    }
}
