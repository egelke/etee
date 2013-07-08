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
 * along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using Siemens.EHealth.Client.Sso.Sts;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Description;
using Siemens.EHealth.Client.Sso.WA;
using Egelke.EHealth.Client.GenIns;
using NUnit.Framework;



namespace Siemens.EHealth.Client.CodageTest
{
    [TestFixture]
    public class GenInsExamples
    {

        [Test]
        public void ConfigViaConfig()
        {
            GenericInsurabilityPortTypeClient client = new GenericInsurabilityPortTypeClient("DoctorEP");

            DoTest(client);
        }

        private static void setHospital(GetInsurabilityAsXmlOrFlatRequestType request)
        {
            request.CommonInput.Origin.SiteID = new ValueRefString();
            request.CommonInput.Origin.SiteID.Value = "2790";
            request.CommonInput.Origin.CareProvider = new CareProviderType();
            request.CommonInput.Origin.CareProvider.Nihii = new NihiiType();
            request.CommonInput.Origin.CareProvider.Nihii.Quality = "hospital";
            request.CommonInput.Origin.CareProvider.Nihii.Value = new ValueRefString();
            request.CommonInput.Origin.CareProvider.Nihii.Value.Value = "71022212000";
            request.CommonInput.Origin.CareProvider.Organization = new IdType();
            request.CommonInput.Origin.CareProvider.Organization.Nihii = request.CommonInput.Origin.CareProvider.Nihii;
        }

        private static void setDoctor(GetInsurabilityAsXmlOrFlatRequestType request)
        {
            request.CommonInput.Origin.CareProvider = new CareProviderType();
            request.CommonInput.Origin.CareProvider.Nihii = new NihiiType();
            request.CommonInput.Origin.CareProvider.Nihii.Quality = "doctor";
            request.CommonInput.Origin.CareProvider.Nihii.Value = new ValueRefString();
            request.CommonInput.Origin.CareProvider.Nihii.Value.Value = "19997341001";
            request.CommonInput.Origin.CareProvider.PhysicalPerson = new IdType();
            request.CommonInput.Origin.CareProvider.PhysicalPerson.Name = new ValueRefString();
            request.CommonInput.Origin.CareProvider.PhysicalPerson.Name.Value = "André Brouckaert";
            request.CommonInput.Origin.CareProvider.PhysicalPerson.Ssin = new ValueRefString();
            request.CommonInput.Origin.CareProvider.PhysicalPerson.Ssin.Value = "79021802145";
        }

        private static void DoTest(GenericInsurabilityPortTypeClient client)
        {
            GetInsurabilityAsXmlOrFlatRequestType request = new GetInsurabilityAsXmlOrFlatRequestType();

            //Create common input with info about the requestor, must match SAML
            request.CommonInput = new CommonInputType();
            request.CommonInput.InputReference = "PRIG1234567890";
            request.CommonInput.Request = new RequestType1();
            request.CommonInput.Request.IsTest = false;
            request.CommonInput.Origin = new OriginType();
            request.CommonInput.Origin.Package = new PackageType();
            request.CommonInput.Origin.Package.Name = new ValueRefString();
            request.CommonInput.Origin.Package.Name.Value = "eH-I Test";
            request.CommonInput.Origin.Package.License = new LicenseType();
            request.CommonInput.Origin.Package.License.Username = "ehi";
            request.CommonInput.Origin.Package.License.Password = "eHIpwd05";
            //request.CommonInput.Origin.Package.License.Username = "siemens";
            //request.CommonInput.Origin.Package.License.Password = "n7z6Y(S8+X";
            setDoctor(request);
            //setHospital(request);

            //Create record common input, contains additional tracking info
            request.RecordCommonInput = new RecordCommonInputType();
            request.RecordCommonInput.InputReferenceSpecified = true;
            request.RecordCommonInput.InputReference = new decimal(1234567890123L);

            //Create actual request (attributes should not be provided)
            request.Request = new SingleInsurabilityRequestType();
            request.Request.CareReceiverId = new CareReceiverIdType();
            request.Request.CareReceiverId.Inss = "23011411057"; //"75042628553";
            request.Request.InsurabilityRequestDetail = new InsurabilityRequestDetailType();
            request.Request.InsurabilityRequestDetail.Period = new PeriodType();
            request.Request.InsurabilityRequestDetail.Period.PeriodStartSpecified = true;
            request.Request.InsurabilityRequestDetail.Period.PeriodStart = DateTime.UtcNow;
            request.Request.InsurabilityRequestDetail.Period.PeriodEndSpecified = true;
            request.Request.InsurabilityRequestDetail.Period.PeriodEnd = DateTime.UtcNow;
            request.Request.InsurabilityRequestDetail.InsurabilityContactType = InsurabilityContactTypeType.ambulatory_care;
            request.Request.InsurabilityRequestDetail.InsurabilityRequestType = InsurabilityRequestTypeType.information;

            //Make call
            GetInsurabilityResponseType insResp = client.getInsurability(request);

            //Verify result
            Assert.AreEqual("200", insResp.Status.Code);
            CareReceiverDetailType crDetail = insResp.Response.Items.OfType<CareReceiverDetailType>().FirstOrDefault();
            CareReceiverIdType crId = insResp.Response.Items.OfType<CareReceiverIdType>().FirstOrDefault();
            InsurabilityResponseDetailType rspDetail = insResp.Response.Items.OfType<InsurabilityResponseDetailType>().FirstOrDefault();
            MessageFaultType fault = insResp.Response.Items.OfType<MessageFaultType>().FirstOrDefault();

            if (fault != null)
            {
                foreach(DetailType detail in fault.Details) {
                    Assert.Inconclusive("Error at {1}: {0} ({2})", detail.DetailCode, detail.Location, detail.Message.Value);
                }
                if (fault.MultiIO.Length > 0)
                {
                    Assert.Inconclusive("Multiple affilications where detected: {0}", fault.MultiIO);
                }
                Assert.Fail("Error by {1}: {0} ({2})", fault.FaultCode, fault.FaultSource, fault.Message);
            }

            //Assert.AreEqual("BROUCKAERT", crDetail.LastName);
            //Assert.IsTrue(rspDetail.InsurabilityList.InsurabilityItem.Length > 0);
        }
    }
}
