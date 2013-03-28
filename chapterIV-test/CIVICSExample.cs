using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Egelke.EHealth.Client.ChapterIV;
using System.ServiceModel;
using System.Xml;

namespace Egelke.EHealth.Client.ChapterIVTest
{
    [TestClass]
    public class CIVICSExample
    {
        [TestMethod]
        public void ConfigViaFile()
        {
            SamcivicsPortTypeClient client = new SamcivicsPortTypeClient("CivicsForDoctor");

            ParagraphRequestType request = new ParagraphRequestType();
            request.language = LanguageType.nl;
            request.chapterName = "IV";
            request.paragraphName = "440100";


            try
            {
                GetParagraphIncludedSpecialitiesResponseType response = client.getParagraphIncludedSpecialities(request);

                AtmAndChildrenType[] atmList = response.atmList;
                //do something with the list...
            }
            catch (FaultException<BusinessError> e)
            {
                XmlNode[] detailNodes = e.Detail.Nodes;
                XmlNode code = detailNodes.Where(n => n.Name == "Code").Single();
                XmlNode message = detailNodes.Where(n => n.Name == "Message").Single();
                Assert.Fail(code.InnerText + ": " + message.InnerText);
            }

        }
    }
}
