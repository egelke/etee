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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Siemens.EHealth.Client.Tool;
using System.Security.Cryptography.X509Certificates;

namespace Siemens.EHealth.Client.UnitTest
{
    [TestClass]
    public class EHealthP12Test
    {
        [TestMethod]
        public void CheckKeysInDummy()
        {
            EHealthP12 p12 = new EHealthP12("dummy.p12", "test001");
            Assert.AreEqual(2, p12.Keys.Count);
        }

        [TestMethod]
        public void CheckAuthInDymmy()
        {
            EHealthP12 p12 = new EHealthP12("dummy.p12", "test001");
            X509Certificate2 cert = p12["authenication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);
        }

        [TestMethod]
        public void CheckEncInDymmy()
        {
            EHealthP12 p12 = new EHealthP12("dummy.p12", "test001");
            X509Certificate2 cert = p12["encryption"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);
        }

        [TestMethod]
        [ExpectedException(typeof(KeyNotFoundException))]
        public void CheckNonExistingInDymmy()
        {
            EHealthP12 p12 = new EHealthP12("dummy.p12", "test001");
            X509Certificate2 cert = p12["other"];
        }
    }
}
