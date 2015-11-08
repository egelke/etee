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
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
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
using Siemens.EHealth.Client.ConsultRn;



namespace Siemens.EHealth.Client.RnTest
{
    [TestClass]
    public class SearchBySsinExamples
    {
        private static SearchBySSINRequest request;

        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            request = new SearchBySSINRequest();
            request.ApplicationID = "79021802145";
            request.Inscription = new InscriptionType();
            request.Inscription.SSIN = "79021802145";
            request.Inscription.Period = new PeriodType();
            request.Inscription.Period.BeginDate = DateTime.Now.AddDays(-1.0);
            request.Inscription.Period.EndDateSpecified = false;
        }

        [TestMethod]
        public void ConfigViaCode()
        {
            //create service stub
            SearchBySsinClient client = new SearchBySsinClient(new StsBinding(), new EndpointAddress(new Uri("https://services-acpt.ehealth.fgov.be/consultRN/identifyPerson/v1")));
            client.Endpoint.Behaviors.Remove<ClientCredentials>();
            client.Endpoint.Behaviors.Add(new OptClientCredentials());
            client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "9c4227f1b9c7a52823829837f1a2e80690da8010");
 
            //Call with prepared request
            SearchBySSINReply response = client.Search(request);

            //Verify result
            Assert.AreEqual(response.Status.Message[0].Value, "100", response.Status.Code);
            Assert.AreEqual(request.Inscription.SSIN, response.Person.SSIN);
        }

        [TestMethod]
        public void ConfigViaFile()
        {
            //create service stub
            SearchBySsinClient client = new SearchBySsinClient("Ssin");

            //Call with prepared request
            SearchBySSINReply response = client.Search(request);

            //Verify result
            Assert.AreEqual(response.Status.Message[0].Value, "100", response.Status.Code);
            Assert.AreEqual(request.Inscription.SSIN, response.Person.SSIN);
        }
    }
}
