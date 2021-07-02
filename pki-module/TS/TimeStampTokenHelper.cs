/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014-2015 Egelke BVBA
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
using BC = Org.BouncyCastle.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Diagnostics;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Helper methods of TimeStampTokens.
    /// </summary>
    public static class TimeStampTokenHelper
    {
        private static TraceSource trace = new TraceSource("Egelke.EHealth.Client.Pki");

        private static readonly TimeSpan ClockSkewness = new TimeSpan(0, 5, 0);

        /// <summary>
        /// Parses a TimeStampToken from binary format to BouncyCastle object format.
        /// </summary>
        /// <param name="tst">The time-stamp-token (the token itself, not the response)</param>
        /// <returns>The BouncyCastle object</returns>
        public static TimeStampToken ToTimeStampToken(this byte[] tst)
        {
            return new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(tst));
        }

        /// <summary>
        /// Check if the timestamp matches the data
        /// </summary>
        /// <param name="tst">The timestamp</param>
        /// <param name="data">The data to match</param>
        /// <returns><c>true</c> when there is a match, <c>false</c> otherwise</returns>
        public static bool IsMatch(this TimeStampToken tst, Stream data)
        {
            //check if we can verify the time-stamp
            if (tst.TimeStampInfo.HashAlgorithm.Parameters != DerNull.Instance)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "The time-stamp {0} contains hash parameters {1} which isn't supported", tst.TimeStampInfo.SerialNumber, tst.TimeStampInfo.HashAlgorithm.Parameters);
                throw new NotSupportedException("Only hash algorithms without parameters are currently supported for timestamps");
            }
            if (tst.TimeStampInfo.Nonce != null)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "The time-stamp {0} contains a Nonce which isn't supported", tst.TimeStampInfo.SerialNumber, tst.TimeStampInfo.HashAlgorithm.Parameters);
                throw new NotSupportedException("Time-stamp with a nonce isn't supported");
            }

            //create the hash according to the specs of the time-stamp
            var hashAlogOid = new Oid(tst.TimeStampInfo.HashAlgorithm.ObjectID.Id);
            var hashAlgo = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlogOid.FriendlyName);
            byte[] signatureValueHashed = hashAlgo.ComputeHash(data);

            //verify the hash value
            byte[] timestampHash = tst.TimeStampInfo.TstInfo.MessageImprint.GetHashedMessage();

            trace.TraceEvent(TraceEventType.Verbose, 0, "Comparing the calculated hash ({3}) {1} with {2} for TST {0}", tst.TimeStampInfo.SerialNumber,
                Convert.ToBase64String(signatureValueHashed), Convert.ToBase64String(timestampHash), hashAlogOid.FriendlyName);
            return ((IStructuralEquatable)signatureValueHashed).Equals(timestampHash, StructuralComparisons.StructuralEqualityComparer);
        }

        private static BC::X509Certificate GetSigner(this TimeStampToken tst, X509Certificate2Collection extraStore)
        {
            //Get the info from the token
            IEnumerator signers = tst.GetCertificates("Collection").GetMatches(tst.SignerID).GetEnumerator();

            //Get the one and only one signer
            if (signers.MoveNext()) return (BC::X509Certificate)signers.Current;

            //No signer found, lets try the extra store
            List<BC::X509Certificate> bcExtraList = extraStore.Cast<X509Certificate2>()
                .Select(c => DotNetUtilities.FromX509Certificate(c))
                .ToList();
            IX509Store bcExtraStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(bcExtraList));

            signers = bcExtraStore.GetMatches(tst.SignerID).GetEnumerator();
            if (signers.MoveNext()) return (BC::X509Certificate)signers.Current;

            return null;
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static Timestamp Validate(this TimeStampToken tst)
        {
            return tst.Validate(null, new List<CertificateList>(), new List<BasicOcspResponse>(), null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static async Task<Timestamp> ValidateAsync(this TimeStampToken tst)
        {
            return await tst.ValidateAsync(null, new List<CertificateList>(), new List<BasicOcspResponse>(), null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="extraCerts">Extra intermediate certificates</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static Timestamp Validate(this TimeStampToken tst, X509Certificate2Collection extraCerts)
        {
            return tst.Validate(extraCerts, new List<CertificateList>(), new List<BasicOcspResponse>(), null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="extraCerts">Extra intermediate certificates</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static async Task<Timestamp> ValidateAsync(this TimeStampToken tst, X509Certificate2Collection extraCerts)
        {
            return await tst.ValidateAsync(extraCerts, new List<CertificateList>(), new List<BasicOcspResponse>(), null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static Timestamp Validate(this TimeStampToken tst, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps)
        {
            return tst.Validate(null, crls, ocsps, null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static async Task<Timestamp> ValidateAsync(this TimeStampToken tst, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps)
        {
            return await tst.ValidateAsync(null, crls, ocsps, null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="extraCerts">Extra intermediate certificates</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static Timestamp Validate(this TimeStampToken tst, X509Certificate2Collection extraCerts, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps)
        {
            return tst.Validate(extraCerts, crls, ocsps, null);
        }

        /// <summary>
        /// Validates the time-stamp token trusting the time of the token itself
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="extraCerts">Extra intermediate certificates</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static async Task<Timestamp> ValidateAsync(this TimeStampToken tst, X509Certificate2Collection extraCerts, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps)
        {
            return await tst.ValidateAsync(extraCerts, crls, ocsps, null);
        }

        /// <summary>
        /// Validates the time-stamp token with a specified trusted time.
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <param name="trustedTime">The trusted time, <c>null</c> for the timestamp time</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static Timestamp Validate(this TimeStampToken tst, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, DateTime? trustedTime)
        {
            return tst.Validate(null, crls, ocsps, trustedTime);
        }

        /// <summary>
        /// Validates the time-stamp token in case of arbitration or with a specified trusted time.
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <param name="trustedTime">The trusted time, <c>null</c> for the timestamp time</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static async Task<Timestamp> ValidateAsync(this TimeStampToken tst, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, DateTime? trustedTime)
        {
            return await tst.ValidateAsync(null, crls, ocsps, trustedTime);
        }

        /// <summary>
        /// Validates the time-stamp token with a specified trusted time.
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="extraCerts">Extra intermediate certificates</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <param name="trustedTime">The trusted time, <c>null</c> for the timestamp time</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static Timestamp Validate(this TimeStampToken tst, X509Certificate2Collection extraCerts, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, DateTime? trustedTime)
        {
            var value = tst.CreateTimestamp();

            //check if the indicated certificate is the signer
            X509Certificate2 signer = tst.CheckSigner(value, extraCerts);

            //check and extract the cert
            var extraStore = tst.GetExtraStore();
            if (extraCerts != null) extraStore.AddRange(extraCerts);

            //get the validation time
            DateTime validationTime = value.GetValidationTime(trustedTime);

            //build the chain
            value.CertificateChain = signer.BuildChain(validationTime, extraStore, crls, ocsps); //we assume time-stamp signers aren't suspended, only permanently revoked

            //get the renewal time
            value.RenewalTime = value.CertificateChain.GetMinNotAfter();

            return value;
        }

        /// <summary>
        /// Validates the time-stamp token in case of arbitration or with a specified trusted time.
        /// </summary>
        /// <param name="tst">The timestamp to validate</param>
        /// <param name="extraCerts">Extra intermediate certificates</param>
        /// <param name="crls">Known Crl's, new retrieved crl's will be added here</param>
        /// <param name="ocsps">Known Ocsp's, new retrieved ocsp's will be added here</param>
        /// <param name="trustedTime">The trusted time, <c>null</c> for the timestamp time</param>
        /// <returns>The validation chain of the signing certificate</returns>
        public static async Task<Timestamp> ValidateAsync(this TimeStampToken tst, X509Certificate2Collection extraCerts, IList<CertificateList> crls, IList<BasicOcspResponse> ocsps, DateTime? trustedTime)
        {
            var value = tst.CreateTimestamp();

            //check if the indicated certificate is the signer
            X509Certificate2 signer = tst.CheckSigner(value, extraCerts);

            //check and extract the cert
            var extraStore = tst.GetExtraStore();
            if (extraCerts != null) extraStore.AddRange(extraCerts);

            //get the validation time
            DateTime validationTime = value.GetValidationTime(trustedTime);

            //build the chain
            value.CertificateChain = await signer.BuildChainAsync(validationTime, extraStore, crls, ocsps); //we assume time-stamp signers aren't suspended, only permanently revoked

            //get the renewal time
            value.RenewalTime = value.CertificateChain.GetMinNotAfter();

            return value;
        }

        private static Timestamp CreateTimestamp(this TimeStampToken tst)
        {
            var value = new Timestamp();
            value.Time = DateTime.SpecifyKind(tst.TimeStampInfo.GenTime, DateTimeKind.Utc);
            value.TimestampStatus = new List<X509ChainStatus>();
            X509ChainStatus status = new X509ChainStatus();
            status.Status = X509ChainStatusFlags.NoError;
            value.TimestampStatus.Add(status);
            return value;
        }

        private static X509Certificate2 CheckSigner(this TimeStampToken tst, Timestamp value, X509Certificate2Collection extraCerts)
        {
            BC.X509Certificate signerBc = tst.GetSigner(extraCerts);
            if (signerBc == null)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "The signer of the time-stamp {0} isn't found", tst.TimeStampInfo.SerialNumber);
                X509CertificateHelper.AddErrorStatus(value.TimestampStatus, null, X509ChainStatusFlags.NotSignatureValid, "Signer not found");
                return null;
            }

            //check the signature
            try
            {
                tst.Validate(signerBc);
            }
            catch (Exception e)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "The signature from {1} of the time-stamp {0} is invalid: {2}", tst.TimeStampInfo.SerialNumber, signerBc.SubjectDN, e.Message);
                X509CertificateHelper.AddErrorStatus(value.TimestampStatus, null, X509ChainStatusFlags.NotSignatureValid, "Time-stamp not signed by indicated certificate: " + e.Message);
            }

            //check if the certificate may be used for time-stamping
            IList signerExtKeyUsage = signerBc.GetExtendedKeyUsage();
            if (!signerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.8"))
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "The signer {1} of the time-stamp {0} isn't allowed to sign timestamps", tst.TimeStampInfo.SerialNumber, signerBc.SubjectDN);
                X509CertificateHelper.AddErrorStatus(value.TimestampStatus, null, X509ChainStatusFlags.NotSignatureValid, "The certificate may not be used for timestamps");
            }

            return new X509Certificate2(signerBc.GetEncoded());
        }

        private static X509Certificate2Collection GetExtraStore(this TimeStampToken tst)
        {
            var extraStore = new X509Certificate2Collection();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in tst.GetCertificates("Collection").GetMatches(null))
            {
                extraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }
            return extraStore;
        }

        private static DateTime GetValidationTime(this Timestamp value, DateTime? trustedTime)
        {
            return trustedTime != null ? trustedTime.Value : value.Time;
        }
    }
}
