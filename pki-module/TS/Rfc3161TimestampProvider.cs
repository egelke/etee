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
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Time-stamp provided via the RFC3161 protocol.
    /// </summary>
    /// <remarks>
    /// Get a time-stamp via the HTTP protocol.
    /// </remarks>
    public class Rfc3161TimestampProvider : ITimestampProviderAsync
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
            TimeStampRequest tspReq = CreateRfc3161RequestBody(hash, digestMethod);

            Stream postStream;
            byte[] tsprBytes = tspReq.GetEncoded();
            HttpWebRequest post = CreateRfc3161WebRequest(tsprBytes, out postStream);
            trace.TraceEvent(TraceEventType.Information, 0, "retrieving time-stamp of {0} from {1}", Convert.ToBase64String(hash), address);

            postStream.Write(tsprBytes, 0, tsprBytes.Length);

            using (var response = (HttpWebResponse)post.GetResponse())
            {
                Stream responseStream = response.GetResponseStream();

                CheckRfc3161WebResponse(response);

                MemoryStream rspStream = new MemoryStream();
                responseStream.CopyTo(rspStream);
                return ParseRfc3161ResponseBody(rspStream.ToArray(), tspReq);
            }
        }

        /// <summary>
        /// Gets a time-stamp of the provided address via the RFC3161.
        /// </summary>
        /// <param name="hash">The has to get the time-stamp from</param>
        /// <param name="digestMethod">The algorithm used to calculate the hash</param>
        /// <returns>The time-stamp token in binary (encoded) format</returns>
        /// <exception cref="WebException">When the TSA returned a http-error</exception>
        /// <exception cref="TspValidationException">When the TSA returns an invalid time-stamp response</exception>
        public async Task<byte[]> GetTimestampFromDocumentHashAsync(byte[] hash, string digestMethod)
        {
            TimeStampRequest tspReq = CreateRfc3161RequestBody(hash, digestMethod);

            Stream postStream;
            byte[] tsprBytes = tspReq.GetEncoded();
            HttpWebRequest post = CreateRfc3161WebRequest(tsprBytes, out postStream);
            trace.TraceEvent(TraceEventType.Information, 0, "retrieving time-stamp of {0} from {1}", Convert.ToBase64String(hash), address);
            
            await postStream.WriteAsync(tsprBytes, 0, tsprBytes.Length);

            using (var response = (HttpWebResponse)post.GetResponse())
            {
                MemoryStream rspStream = new MemoryStream();
                Task rspCopy = response.GetResponseStream().CopyToAsync(rspStream);

                CheckRfc3161WebResponse(response);

                await rspCopy;

                return ParseRfc3161ResponseBody(rspStream.ToArray(), tspReq);
            }
        }

        private TimeStampRequest CreateRfc3161RequestBody(byte[] hash, string digestMethod)
        {
            String digestOid = CryptoConfig.MapNameToOID(CryptoConfig.CreateFromName(digestMethod).GetType().ToString());

            TimeStampRequestGenerator tsprg = new TimeStampRequestGenerator();
            tsprg.SetCertReq(true);
            return tsprg.Generate(digestOid, hash);
        }

        private HttpWebRequest CreateRfc3161WebRequest(byte[] tspr, out Stream postStream)
        {
            var post = (HttpWebRequest)WebRequest.Create(address);
            post.ContentType = "application/timestamp-query";
            post.Method = "POST";
            post.ContentLength = tspr.Length;
            postStream = post.GetRequestStream();
            return post;
        }

        private void CheckRfc3161WebResponse(HttpWebResponse webResponse)
        {

            if (webResponse.StatusCode != HttpStatusCode.OK
                || webResponse.ContentType != "application/timestamp-reply")
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status or content for time-stamp reply: " + webResponse.StatusDescription);
                throw new ApplicationException("Response with invalid status or content type of the TSA: " + webResponse.StatusDescription);
            }
        }

        private byte[] ParseRfc3161ResponseBody(byte[] rspBody, TimeStampRequest tspr)
        {
            TimeStampResponse tsResponse = new TimeStampResponse(rspBody);
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
