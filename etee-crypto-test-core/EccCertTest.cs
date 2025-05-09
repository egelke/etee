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
 * along with .Net ETEE for eHealth.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Text;
using System.Collections.Generic;

using Egelke.EHealth.Etee.Crypto.Sender;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Resources;
using Egelke.EHealth.Etee.Crypto;
using ETEE = Egelke.EHealth.Etee.Crypto;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Receiver;
using System.Security.Cryptography;
using System.Collections.ObjectModel;
using Egelke.EHealth.Etee.Crypto.Utils;
using Egelke.EHealth.Etee.Crypto.Status;
using System.Configuration;
using System.Collections.Specialized;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Security;
using Egelke.EHealth.Etee.Crypto.Store;
using System.Diagnostics;
using Egelke.EHealth.Client.Pki;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Egelke.eHealth.ETEE.Crypto.Test
{

    [TestClass]
    public class EccCertTest
    {
        public TraceSource trace = new TraceSource("Egelke.EHealth.Etee.Test");

        const String clearMessage = "This is a secret message from Bryan for Fred";

        static EHealthP12 bryan;

        static EncryptionToken fred;


        [ClassInitialize]
        public static void InitializeClass(TestContext ctx)
        {
            //Fred
            fred = new EncryptionToken(File.ReadAllBytes("ecc/fred.etk"));

            //Bryan
            bryan = new EHealthP12("ecc/bryan.p12", "Test_001");
        }

        [TestMethod]
        public void Seal()
        {
            IDataSealer sealer = new EhDataSealerFactory(Config.LoggerFactory).Create(Level.B_Level, bryan);
            Stream output = sealer.Seal(new MemoryStream(Encoding.UTF8.GetBytes(clearMessage)), fred);
        }
        
     
    }
}
