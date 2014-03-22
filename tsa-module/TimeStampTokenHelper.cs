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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BC=Org.BouncyCastle.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Egelke.EHealth.Client.Tsa
{
    /// <summary>
    /// Helper methods of TimeStampTokens.
    /// </summary>
    public static class TimeStampTokenHelper
    {
        /// <summary>
        /// Parses a TimeStampToken from binary format to BouncyCastle object format.
        /// </summary>
        /// <param name="tst">The timestamptoken (the token itself, not the response)</param>
        /// <returns>The BouncyCastle object</returns>
        public static TimeStampToken ToTimeStampToken(this byte[] tst)
        {
            return new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(tst));
        }

        public static bool IsMatch(this TimeStampToken tst, Stream data)
        {
            //check if we can verify the timestamp
            if (tst.TimeStampInfo.HashAlgorithm.Parameters != DerNull.Instance)
                throw new NotSupportedException("Only hash algorithms without params are currently supported for timestamps");
            if (tst.TimeStampInfo.Nonce != null)
                throw new NotSupportedException("Timestamp with a nonce isn't supported");

            //create the hash according to the specs of the timestamp
            var hashAlogOid = new Oid(tst.TimeStampInfo.HashAlgorithm.ObjectID.Id);
            var hashAlgo = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlogOid.FriendlyName);
            byte[] signatureValueHashed = hashAlgo.ComputeHash(data);

            //verify the hash value
            byte[] timestampHash = tst.TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();
            return ((IStructuralEquatable)signatureValueHashed).Equals(timestampHash, StructuralComparisons.StructuralEqualityComparer);
        }

        private static BC::X509Certificate GetSigner(this TimeStampToken tst)
        {
            //Get the info from the token
            BC::X509Certificate signer;
            IEnumerator signers = tst.GetCertificates("Collection").GetMatches(tst.SignerID).GetEnumerator();
            
            //Get the one and only one signer
            if (!signers.MoveNext()) return null;
            signer = (BC::X509Certificate)signers.Current;

            return signer;
        }

        public static Timestamp Validate(this TimeStampToken tst)
        {
            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            return tst.Validate(ref crls, ref ocsps);
        }

        public static Timestamp Validate(this TimeStampToken tst, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps)
        {
            return tst.Validate(ref crls, ref ocsps, null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tst"></param>
        /// <param name="crls"></param>
        /// <param name="ocsps"></param>
        /// <param name="trustedTime">The trusted time in case of arbitration, <c>null</c> to trust the indicated time (not arbitration)</param>
        /// <returns>The validation chain of the signing certificate</returns>
        /// <exception cref="InvalidTokenException">When the token isn't signed by the indicated certificate</exception>
        public static Timestamp Validate(this TimeStampToken tst, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps, DateTime? trustedTime)
        {
            var value = new Timestamp();
            value.TimestampStatus = new List<X509ChainStatus>();

            //check if the indicated certificate is the signer
            BC::X509Certificate signerBc = tst.GetSigner();
            if (signerBc == null)
            {
                X509ChainStatus status = new X509ChainStatus();
                status.Status = X509ChainStatusFlags.NotSignatureValid;
                status.StatusInformation = "Signer not found";
                X509CertificateHelper.AddErrorStatus(value.TimestampStatus, status);
            }
            else
            {
                try
                {
                    tst.Validate(signerBc);
                }
                catch (Exception e)
                {
                    X509ChainStatus status = new X509ChainStatus();
                    status.Status = X509ChainStatusFlags.NotSignatureValid;
                    status.StatusInformation = "Timestamp not signed by indicated certificate: " + e.Message;
                    X509CertificateHelper.AddErrorStatus(value.TimestampStatus, status);
                }
            }

            //Get some info
            value.Time = tst.TimeStampInfo.GenTime;
            DateTime validationTime = trustedTime != null ? trustedTime.Value : value.Time;
            var extraStore = new X509Certificate2Collection();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in tst.GetCertificates("Collection").GetMatches(null))
            {
                extraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }

            //Check the chain
            value.CertificateChain = (new X509Certificate2(signerBc.GetEncoded())).BuildChain(value.Time, extraStore, ref crls, ref ocsps, validationTime); //we assume 'timestamp signers aren't suspended, only permanently revoked

            //get the renewal time
            value.RenewalTime = DateTime.MaxValue;
            foreach (ChainElement chainE in value.CertificateChain.ChainElements)
            {
                if (chainE.Certificate.NotAfter < value.RenewalTime)
                {
                    value.RenewalTime = chainE.Certificate.NotAfter;
                }
            }

            //check if the certificate may be used for timestamping
            IList signerExtKeyUsage = signerBc.GetExtendedKeyUsage();
            if (!signerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.8"))
            {
                X509ChainStatus status = new X509ChainStatus();
                status.Status = X509ChainStatusFlags.NotValidForUsage;
                status.StatusInformation = "The certificate may not be used for timestamps";

                X509CertificateHelper.AddErrorStatus(value.TimestampStatus, status);
            }

            if (value.TimestampStatus.Count == 0) {
                X509ChainStatus status = new X509ChainStatus();
                status.Status = X509ChainStatusFlags.NoError;
                value.TimestampStatus.Add(status);
            }
            return value;
        }
    }
}
