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
        public static TimeStampToken Parse(byte[] tst)
        {
            return new TimeStampToken(new Org.BouncyCastle.Cms.CmsSignedData(tst));
        }

        public static void IsMatch(this TimeStampToken tst, Stream data)
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
            IX509Store store = tst.GetCertificates("Collection");
            IEnumerator signers = store.GetMatches(tst.SignerID).GetEnumerator();
            
            //Get the one and only one signer
            if (!signers.MoveNext()) throw new InvalidTokenException("No certificates present in the timestamp");
            signer = (BC::X509Certificate)signers.Current;
            if (signers.MoveNext()) throw new InvalidTokenException("Multiple matching certificates present in the timstamp");

            return signer;
        }


        public static void Validate(this TimeStampToken tst)
        {
            tst.Validate(null, null);
        }

        public static void Validate(this TimeStampToken tst, IList<X509Crl> crls, IList<BasicOcspResp> ocsps)
        {
            tst.Validate(crls, ocsps, false);
        }

        public static void Validate(this TimeStampToken tst, IList<X509Crl> crls, IList<BasicOcspResp> ocsps, bool forArbitration, params TimeStampToken[] archiveTsts)
        {
            if (archiveTsts != null && archiveTsts.Length > 0) throw new NotSupportedException("The library currently doesn't support archiving timestamps");
            
            bool revocationProvided = crls != null || ocsps != null;
            BC::X509Certificate signer = tst.GetSigner();

            //check if the indicated certificate is the signer
            try
            {
                tst.Validate(signer);
            }
            catch (Exception e)
            {
                throw new InvalidTokenException("The timestamp isn't issued by the TSA provided in the timestamp", e);
            }

            //check if the certificate may be used for timestamping
            IList signerExtKeyUsage = signer.GetExtendedKeyUsage();
            if (!signerExtKeyUsage.Contains("1.3.6.1.5.5.7.3.8"))
            {
                throw new InvalidTokenException("The certificate used to sign the timestamp token isn't authorized to do so");
            }

            //Check the chain
            X509Chain tsaChain = new X509Chain();
            foreach (Org.BouncyCastle.X509.X509Certificate cert in tst.GetCertificates("Collection").GetMatches(null))
            {
                tsaChain.ChainPolicy.ExtraStore.Add(new X509Certificate2(cert.GetEncoded()));
            }
            tsaChain.ChainPolicy.RevocationMode = revocationProvided ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
            tsaChain.ChainPolicy.VerificationTime = tst.TimeStampInfo.GenTime;
            tsaChain.Build(new X509Certificate2(signer.GetEncoded()));

            if (tsaChain.ChainStatus.Count(x => x.Status == X509ChainStatusFlags.PartialChain) > 0)
            {
                throw new InvalidTokenException("The timestamp TSA chain is incomplete, signer");
            }

            foreach (X509ChainElement chainE in tsaChain.ChainElements)
            {
                if (chainE.ChainElementStatus.Count(x => x.Status != X509ChainStatusFlags.NoError) > 0)
                    throw new InvalidTokenException(String.Format("The timestamp TSA chain contains an invalid certificate '{0}' ({1}: {2})",
                        chainE.Certificate.Subject, chainE.ChainElementStatus[0].Status, chainE.ChainElementStatus[0].StatusInformation));
            }

            //Check the revocation with the provided info
            if (revocationProvided)
            {

            }

            //
            if (forArbitration && revocationProvided)
            {
                
            }
        }

        



        public static void Validate(this TimeStampToken tst, List<X509Certificate2> trustedTsaCerts)
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
