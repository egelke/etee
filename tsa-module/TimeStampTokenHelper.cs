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
        public static TimeStampToken ToTimeSTampToken(this byte[] tst)
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

        public static DateTime GetRenewalTime(this TimeStampToken tst)
        {
            //Build the chain
            X509Chain tsaChain = new X509Chain();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in tst.GetCertificates("Collection").GetMatches(null))
            {
                tsaChain.ChainPolicy.ExtraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }
            tsaChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            tsaChain.Build(new X509Certificate2(tst.GetSigner().GetEncoded()));

            //get the shortest expire time
            DateTime renewalTime = DateTime.MaxValue;
            foreach (X509ChainElement chainE in tsaChain.ChainElements)
            {
                if (chainE.Certificate.NotAfter < renewalTime)
                {
                    renewalTime = chainE.Certificate.NotAfter;
                }
            }
            return renewalTime;
        }

        public static BC::X509Certificate GetSigner(this TimeStampToken tst)
        {
            //Get the info from the token
            BC::X509Certificate signer;
            IEnumerator signers = tst.GetCertificates("Collection").GetMatches(tst.SignerID).GetEnumerator();
            
            //Get the one and only one signer
            if (!signers.MoveNext()) throw new InvalidTokenException("No certificates present in the timestamp");
            signer = (BC::X509Certificate)signers.Current;
            if (signers.MoveNext()) throw new InvalidTokenException("Multiple matching certificates present in the timstamp");

            return signer;
        }

        public static Chain Validate(this TimeStampToken tst)
        {
            IList<CertificateList> crls = new List<CertificateList>();
            IList<BasicOcspResponse> ocsps = new List<BasicOcspResponse>();
            return tst.Validate(ref crls, ref ocsps);
        }

        public static Chain Validate(this TimeStampToken tst, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps)
        {
            return tst.Validate(ref crls, ref ocsps, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tst"></param>
        /// <param name="crls"></param>
        /// <param name="ocsps"></param>
        /// <param name="forArbitration"></param>
        /// <param name="archiveTsts"></param>
        /// <returns>The validation chain of the signing certificate</returns>
        /// <exception cref="InvalidTokenException">When the token isn't signed by the indicated certificate</exception>
        public static Chain Validate(this TimeStampToken tst, ref IList<CertificateList> crls, ref IList<BasicOcspResponse> ocsps, bool forArbitration, params TimeStampToken[] archiveTsts)
        {
            if (archiveTsts != null && archiveTsts.Length > 0) throw new NotSupportedException("The library currently doesn't support archiving timestamps");
            
            bool revocationProvided = crls != null || ocsps != null;
            BC::X509Certificate signerBc = tst.GetSigner();

            //check if the indicated certificate is the signer
            try
            {
                tst.Validate(signerBc);
            }
            catch (Exception e)
            {
                throw new InvalidTokenException("The timestamp isn't issued by the TSA provided in the timestamp", e);
            }

            //Get some info
            DateTime signingTime = tst.TimeStampInfo.GenTime;
            DateTime trustedTime = forArbitration ? DateTime.UtcNow : signingTime; //you should not trust the time indicated in the timestamp in case of arbitration.
            var extraStore = new X509Certificate2Collection();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in tst.GetCertificates("Collection").GetMatches(null))
            {
                extraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }

            //Check the chain
            Chain tsaChain = (new X509Certificate2(signerBc.GetEncoded())).BuildChain(signingTime, extraStore, ref crls, ref ocsps, trustedTime); //we assume 'timestamp signers aren't suspended, only permanently revoked

            //check if the certificate may be used for timestamping
            IList signerExtKeyUsage = signerBc.GetExtendedKeyUsage();
            if (!signerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.8"))
            {
                X509ChainStatus status = new X509ChainStatus();
                status.Status = X509ChainStatusFlags.NotValidForUsage;
                status.StatusInformation = "The certificate may not be used for timestamps";

                X509CertificateHelper.AddErrorStatus(tsaChain.ChainStatus, status);
                X509CertificateHelper.AddErrorStatus(tsaChain.ChainElements[0].ChainElementStatus, status);
            }

            return tsaChain;
        }
    }
}
