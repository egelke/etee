/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
 *  Copyright (C) 2012 I.M. vzw
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  Foobar is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Tsp;

namespace Egelke.EHealth.Client.Tsa
{
    /// <summary>
    /// Timestamp provider for eHealth as TSA.
    /// </summary>
    /// <remarks>
    /// eHealth has a TSA that uses DSS but defines its own profile that is based on the DSS timestamp profile.
    /// </remarks>
    public class EHealthTimestampProvider : DssTimestampProvider
    {
        /// <summary>
        /// Default constructor using default TSA client of the application configuration.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When this constructor is used, the application configuration is searched for a TSA client with the name "Xades.TSA".
        /// </para>
        /// <para>
        /// The eHealth TSA requires the StsBinding as provided by the eH-I codeplex project.
        /// </para>
        /// </remarks>
        public EHealthTimestampProvider()
            : base()
        {
            profile = "urn:ehealth:profiles:timestamping:2.0";
        }

        /// <summary>
        /// Constructor using a TSA client with the provided configuration.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When this constructor is used, the application configuration is searched for a TSA client with the provided name.
        /// </para>
        /// <para>
        /// The eHealth TSA requires the StsBinding as provided by the eH-I codeplex project.
        /// </para>
        /// </remarks>
        /// <param name="config">The configuration name of the TSA client</param>
        public EHealthTimestampProvider(String config)
            : base(config)
        {
            profile = "urn:ehealth:profiles:timestamping:2.0";
        }

        /// <summary>
        /// Constructor using a provided TSA client.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When this constructor is used, the application configuration isn't used.
        /// </para>
        /// <para>
        /// The eHealth TSA requires the StsBinding as provided by the eH-I codeplex project.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code language="C#">
        /// tsa = new TSA.DSS.TimeStampAuthorityClient(new StsBinding(), new EndpointAddress("https://wwwacc.ehealth.fgov.be/timestampauthority_1_5/timestampauthority"));
        /// tsa.Endpoint.Behaviors.Remove&lt;ClientCredentials&gt;();
        /// tsa.Endpoint.Behaviors.Add(new OptClientCredentials());
        /// tsa.ClientCredentials.ClientCertificate.Certificate = certificate;
        /// var tsProvider = new EHealthTimestampProvider(tsa);
        /// </code>
        /// </example>
        /// <param name="client">The pre-configured instance of the TSA client.</param>
        public EHealthTimestampProvider(DSS.TimeStampAuthorityClient client)
            : base(client)
        {
            profile = "urn:ehealth:profiles:timestamping:2.0";
        }

        /// <summary>
        /// Method used by the library, not not call youself.
        /// </summary>
        /// <param name="hash">The hash on which the digesht must be calculated</param>
        /// <param name="digestMethod">The digest method with which the hash was calculated</param>
        /// <returns>The RFC3161 Timestamp token</returns>
        public override byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            //Translate the digest method name
            string dsMethod;
            switch (digestMethod)
            {
                case "http://www.w3.org/2000/09/xmldsig#sha1":
                    dsMethod = "SHA-1";
                    break;
                case "http://www.w3.org/2001/04/xmlenc#sha256":
                    dsMethod = "SHA-256";
                    break;
                default:
                    throw new ArgumentException("Requested unsupported digest method \"" + digestMethod + "\"", "digestMethod");
            }

            byte[] base64EncodedBytes = base.GetTimestampFromDocumentHash(hash, dsMethod);

            //eHealth double encodes, so we need to decode
            byte[] bytes = Convert.FromBase64String(Encoding.ASCII.GetString(base64EncodedBytes));

            //eHealth returns an TimeStampResp instead of an TimeStampToken 
            TimeStampResponse tsp = new TimeStampResponse(bytes);
            return tsp.TimeStampToken.GetEncoded();
        }
    }
}
