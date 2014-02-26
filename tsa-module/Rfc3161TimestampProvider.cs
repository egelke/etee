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
using System.Net;
using Org.BouncyCastle.Tsp;
using System.IO;
using System.Security.Cryptography;

namespace Egelke.EHealth.Client.Tsa
{
    /// <summary>
    /// Timestamp provided via teh RFC3161 protocol.
    /// </summary>
    /// <remarks>
    /// Get a timestamp via the HTTP protocol.
    /// </remarks>
    public class Rfc3161TimestampProvider : ITimestampProvider
    {
        private Uri address;

        /// <summary>
        /// Constuctor that has the Fedict TSA as destination.
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
        /// Gets a timestamp of the provided address via the RFC3161.
        /// </summary>
        /// <param name="hash">The has to get the timestamp from</param>
        /// <param name="digestMethod">The algorithm used to calculate the hash</param>
        /// <returns>The timestamp token in binary (encoded) format</returns>
        /// <exception cref="WebException">When the TSA returned a http-error</exception>
        /// <exception cref="TspValidationException">When the TSA returns an invalid timestamp response</exception>
        public byte[] GetTimestampFromDocumentHash(byte[] hash, string digestMethod)
        {
            String digestOid = CryptoConfig.MapNameToOID(CryptoConfig.CreateFromName(digestMethod).GetType().ToString());

            TimeStampRequestGenerator tsprg = new TimeStampRequestGenerator();
            tsprg.SetCertReq(true);
            TimeStampRequest tspr = tsprg.Generate(digestOid, hash);
            byte[] tsprBytes = tspr.GetEncoded();

            WebRequest post = WebRequest.Create(address);
            post.ContentType = "application/timestamp-query";
            post.Method = "POST";
            post.ContentLength = tsprBytes.Length;
            using (Stream postStream = post.GetRequestStream())
            {
                postStream.Write(tsprBytes, 0, tsprBytes.Length);
            }
            WebResponse response = post.GetResponse();
            if (response.ContentType != "application/timestamp-reply")
            {
                throw new ApplicationException("Response with invalid content type of the TSA: " + response.ContentType);
            }
            Stream responseStream = response.GetResponseStream();

            TimeStampResponse tsResponse = new TimeStampResponse(responseStream);
            tsResponse.Validate(tspr);

            return tsResponse.TimeStampToken.GetEncoded();
        }
    }
}
