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
using Siemens.EHealth.Client.Sso.Sts;
using System.Security.Cryptography.X509Certificates;



namespace Siemens.EHealth.Client.CodageTest
{
    [TestClass]
    public class Code
    {
        [TestMethod]
        public void Normal()
        {
            //Don't forget to set "ProtectionLevel.Sign" on the CodagePort class.
            Proxy.CodagePortClient client = new Proxy.CodagePortClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be:443/codage_1_0/codage"));
            client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c175242f2454fa00b69b49308f82cae919f8e8f5");
            client.ClientCredentials.ServiceCertificate.SetDefaultCertificate(StoreLocation.LocalMachine, StoreName.AddressBook, X509FindType.FindByThumbprint, "23005f9a30f357dfb265de5277db54c5ff61d34d");

            Proxy.OriginalDataType org1 = new Proxy.OriginalDataType();
            org1.randomize = false;
            org1.id = "1";
            org1.inputData = "79021802145";


            Proxy.EncodeRequestType request = new Proxy.EncodeRequestType();
            request.applicationName = "Test";
            request.originalData = new Proxy.OriginalDataType[] { org1 };

            Proxy.EncodeResponseType response = client.encode(request);
         
            Assert.IsFalse(string.IsNullOrWhiteSpace(response.ticketNumber));
        }
    }
}
