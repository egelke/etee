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
    public class PhoneticSearchExamples
    {
        private static SearchPhoneticRequest request;

        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            request = new SearchPhoneticRequest();
            request.ApplicationID = "79021802145";
            request.PhoneticCriteria = new PhoneticCriteriaType();
            request.PhoneticCriteria.LastName = "Brouckaert";
            request.PhoneticCriteria.FirstName = "Bryan";
            request.PhoneticCriteria.BirthDate = "1979-02-18";
            request.PhoneticCriteria.Gender = new GenderType();
            request.PhoneticCriteria.Gender.Value = GenderPossibility.MALE;
            
        }

        [TestMethod]
        public void ConfigViaCode()
        {
            //create service stub
            SearchPhoneticClient client = new SearchPhoneticClient(new StsBinding(), new EndpointAddress(new Uri("https://services-acpt.ehealth.fgov.be/consultRN/identifyPerson/v1")));
            client.Endpoint.Behaviors.Remove<ClientCredentials>();
            client.Endpoint.Behaviors.Add(new OptClientCredentials());
            client.ClientCredentials.ClientCertificate.SetCertificate(StoreLocation.CurrentUser, StoreName.My, X509FindType.FindByThumbprint, "cf692e24bac7c1d990496573e64ef999468be67e");
 
            //Call with prepared request
            SearchPhoneticReply response = client.Search(request);

            //Verify result
            Assert.AreEqual(response.Status.Message[0].Value, "100", response.Status.Code);
            PersonType bryan = response.Person.Where(p => p.SSIN == "79021802145").Single();
            Assert.AreEqual(bryan.PersonData.Birth.Date, "1979-02-18");
            Assert.AreEqual(bryan.PersonData.Birth.Localisation.Municipality.PostalCode, "8630");
        }

        [TestMethod]
        public void ConfigViaFile()
        {
            //create service stub
            SearchPhoneticClient client = new SearchPhoneticClient("Phonetic");

            //Call with prepared request
            SearchPhoneticReply response = client.Search(request);

            //Verify result
            Assert.AreEqual(response.Status.Message[0].Value, "100", response.Status.Code);
            PersonType bryan = response.Person.Where(p => p.SSIN == "79021802145").Single();
            Assert.AreEqual(bryan.PersonData.Birth.Date, "1979-02-18");
            Assert.AreEqual(bryan.PersonData.Birth.Localisation.Municipality.PostalCode, "8630");
        }
    }
}
