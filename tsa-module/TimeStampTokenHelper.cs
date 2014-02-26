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

namespace Egelke.EHealth.Client.Tsa
{
    /// <summary>
    /// Helper methods of TimeStampTokens.
    /// </summary>
    public class TimeStampTokenHelper
    {
        /// <summary>
        /// Parses a TimeStampToken from binary format to BouncyCastle object format.
        /// </summary>
        /// <param name="tst">The timestamptoken (the token itself, not the response)</param>
        /// <returns>The BouncyCastle object</returns>
        public TimeStampToken Parse(byte[] tst)
        {
            return new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(tst));
        }

        /// <summary>
        /// Checks if the timestamp agains the provided data.
        /// </summary>
        /// <remarks>
        /// The caller must prepare the data depending on the specs (e.g. Xades, eHealth ETEE)
        /// </remarks>
        /// <param name="data">The data that is timestamped</param>
        /// <param name="tst">The timestamp</param>
        /// <param name="revocationModus">If and how revocation information realted to the timestamp should be checked</param>
        /// <returns>The time of the timestamp, normally UTC</returns>
        public DateTime Verify(Stream data, TimeStampToken tst, X509RevocationMode revocationModus)
        {
            CheckMatch(data, tst);
            CheckTrust(tst, revocationModus);

            return tst.TimeStampInfo.GenTime;
        }

        /// <summary>
        /// Checks if the timestamp agains the provided data.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The caller must prepare the data depending on the specs (e.g. Xades, eHealth ETEE).
        /// </para>
        /// <para>
        /// The method does not do any verification on the provided certificates, this is the 
        /// responsability of the caller.
        /// </para>
        /// </remarks>
        /// <param name="data">The data that is timestamped</param>
        /// <param name="tst">The timestamp</param>
        /// <param name="trustedTsaCerts">A set of timestamp certificates that are trusted</param>
        /// <returns>The time of the timestamp, normally UTC</returns>
        public DateTime Verify(Stream data, TimeStampToken tst, List<X509Certificate2> trustedTsaCerts)
        {
            CheckMatch(data, tst);
            CheckTrust(tst, trustedTsaCerts);

            return tst.TimeStampInfo.GenTime;
        }

        private void CheckMatch(Stream data, TimeStampToken tst)
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
            if (!((IStructuralEquatable)signatureValueHashed).Equals(timestampHash, StructuralComparisons.StructuralEqualityComparer))
                throw new InvalidTokenException("The timestamp doesn't match the signature value");
        }

        private void CheckTrust(TimeStampToken tst, X509RevocationMode revocationModus)
        {
            //Get the info from the token
            IX509Store store = tst.GetCertificates("Collection");
            ICollection signerCollection = store.GetMatches(tst.SignerID);
            Org.BouncyCastle.X509.X509Certificate[] signers = new Org.BouncyCastle.X509.X509Certificate[signerCollection.Count];
            signerCollection.CopyTo(signers, 0);

            //Check if the have correct info
            if (signers.Length == 0) throw new InvalidOperationException("No certificates present in the timestamp and not trusted TSA certificate provided, please provide a trusted TSA certificate");
            if (signers.Length > 1) throw new InvalidOperationException("Multiple matching certificates present in the timstamp");

            //check if the indicated certificate is the signer
            try
            {
                tst.Validate(signers[0]);
            }
            catch (Exception e)
            {
                throw new InvalidTokenException("The timestamp isn't issued by the TSA provided in the timestamp", e);
            }

            //check if the certificate may be used for timestamping
            IList signerExtKeyUsage = signers[0].GetExtendedKeyUsage();
            if (!signerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.8"))
            {
                throw new InvalidTokenException("The certificate used to sign the time stamp token isn't authorized to do so");
            }

            //Check the chain
            X509Chain tsaChain = new X509Chain();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in store.GetMatches(null))
            {
                tsaChain.ChainPolicy.ExtraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }
            tsaChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            tsaChain.ChainPolicy.RevocationMode = revocationModus;
            tsaChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            tsaChain.Build(new X509Certificate2(signers[0].GetEncoded()));

            foreach (X509ChainElement chainE in tsaChain.ChainElements)
            {
                if (chainE.ChainElementStatus.Length > 0 && chainE.ChainElementStatus[0].Status != X509ChainStatusFlags.NoError)
                    throw new InvalidTokenException(String.Format("The timestamp TSA chain contains an invalid certificate '{0}' ({1}: {2})",
                        chainE.Certificate.Subject, chainE.ChainElementStatus[0].Status, chainE.ChainElementStatus[0].StatusInformation));
            }
        }

        private void CheckTrust(TimeStampToken tst, List<X509Certificate2> trustedTsaCerts)
        {
            //Convert the provided certificates and retrieve the indicated signer
            Org.BouncyCastle.X509.X509CertificateParser bcCertParser = new Org.BouncyCastle.X509.X509CertificateParser();
            List<Org.BouncyCastle.X509.X509Certificate> bcTrustedTsaCerts = new List<Org.BouncyCastle.X509.X509Certificate>();
            foreach (X509Certificate2 trustedTsaCert in trustedTsaCerts)
            {
                bcTrustedTsaCerts.Add(bcCertParser.ReadCertificate(trustedTsaCert.GetRawCertData()));
            }
            IX509Store bcTrustedTsaCertStore = X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(bcTrustedTsaCerts));
            IEnumerator tsaSigners = bcTrustedTsaCertStore.GetMatches(tst.SignerID).GetEnumerator();

            //check if the indicated signer is the actuall signer
            if (tsaSigners.MoveNext())
            {
                try
                {
                    tst.Validate((Org.BouncyCastle.X509.X509Certificate)tsaSigners.Current);
                }
                catch (Exception e)
                {
                    throw new InvalidTokenException("The timestamp isn't issued by the trusted TSA that was indicated as the signer", e);
                }
            }
            else
            {
                throw new InvalidTokenException("The timestamp isn't issued by one of the trusted TSA");
            }
        }
    }
}
