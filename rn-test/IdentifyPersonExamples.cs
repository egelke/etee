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
using System.ServiceModel.Description;
using Siemens.EHealth.Client.Sso.WA;
using Siemens.EHealth.Client.RnTest.Service_References.phoneticSearch;
using Siemens.EHealth.Client.RnTest.IdentifyPerson;



namespace Siemens.EHealth.Client.RnTest
{
    [TestClass]
    public class IdentifyPersonExamples
    {
        [TestMethod]
        public void ConfigViaCode()
        {
            //create service stub
            IdentifyPersonClient client = new IdentifyPersonClient(new StsBinding(), new EndpointAddress(new Uri("https://services-acpt.ehealth.fgov.be/consultRN/identifyPerson/v1")));
            client.Endpoint.Behaviors.Remove<ClientCredentials>();
            client.Endpoint.Behaviors.Add(new OptClientCredentials());
            client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "c175242f2454fa00b69b49308f82cae919f8e8f5");
 
            SearchBySSINRequest request = new SearchBySSINRequest();
            request.ApplicationID = "YourID";
            request.Inscription = new InscriptionType();
            request.Inscription.SSIN = "79021802145";
            request.Inscription.Period = new PeriodType();
            request.Inscription.Period.BeginDate = DateTime.Now.AddDays(-1.0);
            request.Inscription.Period.EndDateSpecified = false;

            SearchBySSINReply response = client.Search(request);
            Assert.AreEqual(response.Status.Message[0].Value, "100", response.Status.Code);
            Assert.AreEqual(request.Inscription.SSIN, response.Person.SSIN);
        }
    }
}
