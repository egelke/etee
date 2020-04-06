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
 *  eH-I is distributed in the hope that it will be useful,
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
using System.Net;
using Org.BouncyCastle.Tsp;
using System.IO;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Time-stamp provided via the RFC3161 protocol.
    /// </summary>
    /// <remarks>
    /// Get a time-stamp via the HTTP protocol.
    /// </remarks>
    public class Rfc3161TimestampProvider : ITimestampProvider
    {
        private TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");

        private Uri address;

        /// <summary>
        /// Constructor that has the Fedict TSA as destination.
        /// </summary>
        /// <remarks>
        /// You may only use this when you have the explicit agreement of Fedict. 
        /// </remarks>
        public Rfc3161TimestampProvider()
        {
            address = new Uri("http://tsa.belgium.be/connect");
        }

        /// <summary>
        /// Constructor that accept the address of the TSA.
        /// </summary>
        /// <param name="address">The url of the TSA</param>
        public Rfc3161TimestampProvider(Uri address)
        {
            this.address = address;
        }

        /// <summary>
        /// Gets a time-stamp of the provided address via the RFC3161.
        /// </summary>
        /// <param name="hash">The has to get the time-stamp from</param>
        /// <param name="digestMethod">The algorithm used to calculate the hash</param>
        /// <returns>The time-stamp token in binary (encoded) format</returns>
        /// <exception cref="WebException">When the TSA returned a http-error</exception>
        /// <exception cref="TspValidationException">When the TSA returns an invalid time-stamp response</exception>
        public byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            String digestOid = CryptoConfig.MapNameToOID(CryptoConfig.CreateFromName(digestMethod).GetType().ToString());

            TimeStampRequestGenerator tsprg = new TimeStampRequestGenerator();
            tsprg.SetCertReq(true);
            TimeStampRequest tspr = tsprg.Generate(digestOid, hash);
            byte[] tsprBytes = tspr.GetEncoded();

            trace.TraceEvent(TraceEventType.Information, 0, "retrieving time-stamp of {0} from {1}", Convert.ToBase64String(hash), address);
            WebRequest post = WebRequest.Create(address);
            post.ContentType = "application/timestamp-query";
            post.Method = "POST";
            post.ContentLength = tsprBytes.Length;
            using (Stream postStream = post.GetRequestStream())
            {
                postStream.Write(tsprBytes, 0, tsprBytes.Length);
            }
            WebResponse response = post.GetResponse();
            Stream responseStream = response.GetResponseStream();
            if (response.ContentType != "application/timestamp-reply")
            {
                byte[] buffer = (new BinaryReader(responseStream)).ReadBytes(16 * 1024);
                trace.TraceData(TraceEventType.Error, 0, "Invalid http content for time-stamp reply: " + response.ContentType, buffer);
                throw new ApplicationException("Response with invalid content type of the TSA: " + response.ContentType);
            }

            TimeStampResponse tsResponse = new TimeStampResponse(responseStream);
            trace.TraceData(TraceEventType.Verbose, 0, "retrieved time-stamp response", address.ToString(), Convert.ToBase64String(tsResponse.GetEncoded()));

            try
            {
                tsResponse.Validate(tspr);
            }
            catch (Exception e)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "The time-stamp response does not correspond with the request: {0}", e.Message);
                throw e;
            }

            return tsResponse.TimeStampToken.GetEncoded();
        }
    }
}
