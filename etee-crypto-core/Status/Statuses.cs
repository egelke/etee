/*
 * This file is part of .Net ETEE for eHealth.
 * Copyright (C) 2014 Egelke
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
using System.Collections.Generic;
using System.Text;

namespace Egelke.EHealth.Etee.Crypto.Status
{
    /// <summary>
    /// Indicates if object is correct or not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The object depends on where this enum is used.  The object can be the message,
    /// an inner/outer signature, certificate, etk, ...
    /// </para>
    /// <para>
    /// Correct means that the object isn't altered by somebody other then the issuer
    /// and that is conforms to the eHealth requirements.
    /// </para>
    /// </remarks>
    public enum ValidationStatus
    {

        /// <summary>
        /// <para>
        /// The object isn't altered and conforms to eHealth requirements.
        /// </para>
        /// <para>
        /// This result means you can use the object, but you still
        /// have to check if you can trust the issue, <see cref="TrustStatus"/>.
        /// </para>
        /// </summary>
        Valid = 0,

        /// <summary>
        /// <para>
        /// It was impossible to execute all required checks at this time because some information wasn't available.
        /// </para>
        /// <para>
        /// You should not use this object.  Check the <see cref="SecurityInformation.SecurityViolations"/> 
        /// property for the reason and try to fix it (e.g restore Internet
        /// access so the CRL file can be downloaded) and run the verification again on the same object.
        /// </para>
        /// </summary>
        Unsure = 1,

        /// <summary>
        /// <para>
        /// The checks detected a security violation.
        /// </para>
        /// <para>
        /// You may not use this object.  Check the <see cref="SecurityInformation.SecurityViolations"/> 
        /// property for the reason and communicate it to the sender.  The sender should then re-create the object,
        /// this time according to the specs.
        /// </para>
        /// </summary>
        Invalid = 2,
    }

    /// <summary>
    /// Indicates if the object comes from a trusted issuer or not.
    /// </summary>
    public enum TrustStatus : int
    {
        /// <summary>
        /// <para>
        /// The issuer is fully trusted.
        /// </para>
        /// <para>
        /// You should use the object, but only if you trust this specific issuer.  This value
        /// only indicates the issuer is who he claims to be, it does not guarantee that
        /// he is allowed to issue the object for you application.
        /// </para>
        /// </summary>
        Full = 0,

        /// <summary>
        /// <para>
        /// The issuer is not trusted because some checks could not be executed.
        /// </para>
        /// <para>
        /// You should not accept this message, although it is very likely the sender is correct.  
        /// Check the <see cref="SecurityInformation.SecurityViolations"/>  property for the reason.  
        /// If the reason is the sender, you may request the sender to fix it and resend the message. 
        /// If the reason is local, it is sufficient to fix it and redo the validation.
        /// </para>
        /// </summary>
        Unsure = 1,

        /// <summary>
        /// <para>
        ///The issuer is not trusted because some checks failed.
        ///</para>
        ///<para>
        /// You may not accept the message.  The sender information, if present, is probably not correct.
        /// </para>
        /// </summary>
        None = 2
    }

    internal class StatusHelper<TViolation>
    {
        private static readonly Type type = typeof(TViolation);

        public static ValidationStatus GetValidationStatus(TViolation violation)
        {
            return ((ValidationResultAttribute[])type.GetField(Enum.GetName(type, violation)).GetCustomAttributes(typeof(ValidationResultAttribute), false))[0].Result;
        }

        public static TrustStatus GetTrustStatus(TViolation violation)
        {
            return ((TrustLevelAttribute[])type.GetField(Enum.GetName(type, violation)).GetCustomAttributes(typeof(TrustLevelAttribute), false))[0].Level;
        }
    }

    /// <summary>
    /// Detailed security information about an unsealed message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Indicates which parts of the unsealed message there are security issues:
    /// <list type="bullet">
    /// <item>
    /// <description>Sender, the person that sent and signed the message</description>
    /// </item>
    /// <item>
    /// <description>Data, the content (clear) of the message</description>
    /// </item>
    /// <item>
    /// <description>Recipient, the receiver for who the message is intended</description>
    /// </item>
    /// </list>
    /// </para>
    /// </remarks>
    public enum UnsealSecurityViolation
    {
        /// <summary>
        /// <para>
        /// Sender can't be trusted.
        /// </para>
        /// <para>
        /// The sender/issuer information that is in this message can't be trusted.
        /// Check the <see cref="UnsealSecurityInformation.OuterSignature"/> or 
        /// <see cref="UnsealSecurityInformation.InnerSignature"/> properties for
        /// more information.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        UntrustedSender,

        /// <summary>
        /// <para>
        /// Sender trust is unknown.
        /// </para>
        /// <para>
        /// It is unsure if the sender/issuer information that is in this message can be trusted or not.
        /// The sender/issuer information that is in this message can't be trusted.
        /// Check the <see cref="UnsealSecurityInformation.OuterSignature"/> or 
        /// <see cref="UnsealSecurityInformation.InnerSignature"/> properties for
        /// more information.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Unsure)]
        [ValidationResult(ValidationStatus.Valid)]
        SenderTrustUnknown,

        /// <summary>
        /// <para>
        /// Receiver can't be trusted.
        /// </para>
        /// <para>
        /// The receiver, that is you, can't be trusted.  This means an encryption/decryption
        /// certificate is used that is (no longer) valid.
        /// Check the <see cref="UnsealSecurityInformation.Encryption"/> properties for
        /// more information.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        UntrustedRecipient,

        /// <summary>
        /// <para>
        /// The data is invalid.
        /// </para>
        /// <para>
        /// The data validation failed, most likely this is due to the fact that the
        /// data is altered, but it could also mean the sender or receiver information
        /// is changed.  The <see cref="SecurityResult{TViolation}.SecurityResult"/> and 
        /// <see cref="SecurityResult{TViolation}.TrustStatus"/> properties reflect the situation
        /// where the data is altered, but it might as well be the sender and or receiver
        /// that are changed.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        InvalidData,

        /// <summary>
        /// It is unknown if the data is valid or not, most likely because of missing signature information.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Unsure)]
        DataValidityUnkown
    }

    /// <summary>
    /// Detailed security information about a security operation, either signature or encryption.
    /// </summary>
    /// <remarks>
    /// This library does treat signing and encryption in the say way for certain extend.  Both
    /// have a certificate, for signing this is the sender for encryption this is the receiver, which
    /// is called "Subject".  The checks on the subject are exactly the same for signing and encryption.
    /// The checks for the signature itself and the decryption are different, therefore both have
    /// specific violations.
    /// </remarks>
    public enum SecurityViolation
    {
        //[TrustLevel(TrustStatus.None)]
        //[ValidationResult(ValidationStatus.Unsure)]
        //NotEncrypted,

        /// <summary>
        /// <para>
        /// The content is encrypted with an unaccepted algorithm (encryption).
        /// </para>
        /// <para>
        /// The content of an sealed message is never encrypted directly with
        /// the public key of the receiver.  Instaid a (faster) symmetric key
        /// is used to encrypt the content and only the symmetric key itself
        /// is sealed with the public key of the receiver(s).
        /// </para>
        /// <para>
        /// For security reasons, only the most advanced encryption
        /// algorithms are allowed.  This violation occurs when a
        /// less advanced algorithm is used for the encryption of content
        /// by the symmetric key.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotAllowedEncryptionAlgorithm,

        /// <summary>
        /// <para>
        /// The key is encrypted with an unaccepted algorithm (encryption).
        /// </para>
        /// <para>
        /// The content of an sealed message is never encrypted directly with
        /// the public key of the receiver.  Instaid a (faster) symmetric key
        /// is used to encrypt the content and only the symmetric key itself
        /// is sealed with the public key of the receiver(s).
        /// </para>
        /// <para>
        /// For security reasons, only the most advanced encryption
        /// algorithms are allowed.  This violation occurs when a
        /// less advanced algorithm is used for the encryption of the
        /// symmetric key by the public key of the receiver.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotAllowedKeyEncryptionAlgorithm,

        /// <summary>
        /// <para>
        /// The key is encrypted with an unacceptable key size (encryption).
        /// </para>
        /// <para>
        /// The content of an sealed message is never encrypted directly with
        /// the public key of the receiver.  Instaid a (faster) symmetric key
        /// is used to encrypt the content and only the symmetric key itself
        /// is sealed with the public key of the receiver(s).
        /// </para>
        /// <para>
        /// For security reasons, only keys of a certain size are allowed.  
        /// This violation occurs when a the public key of the receiver is
        /// smaller then the minimum size.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotAllowedEncryptionKeySize,

        /// <summary>
        /// <para>
        /// There was no signature present (signing).
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Unsure)]
        NotSigned, //only in case of a cms-signed-message without signature

        /// <summary>
        /// <para>
        /// The signer info wasn't present (signing).
        /// </para>
        /// <para>
        /// Normally a sealed message contains the information about the signer,
        /// if this information is missing it is impossible to verify the
        /// signature and this violation is raised.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Unsure)]
        NotFoundSigner,

        /// <summary>
        /// <para>
        /// The signature was invalid (signing).
        /// </para>
        /// <para>
        /// When this violation is raised, either the data is altered
        /// or the issuer information is substituted.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotSignatureValid,

        /// <summary>
        /// <para>
        /// The digest algorithm for signing isn't allowed (signing).
        /// </para>
        /// <para>
        /// In most cases a signature consist of an encrypted
        /// digest of the content.  Therefore a signature algorithm
        /// consists of a digest algorithm and a encryption algorithm.
        /// The encryption algorithm of the signature is not related
        /// to the encryption algorithm of the encryption.
        /// </para>
        /// <para>
        /// For security reasons only the most advanced algorithms are
        /// allowed.  This violation occurs when the digest algorithm of the 
        /// signature is less advanced then required.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotAllowedSignatureDigestAlgorithm,

        /// <summary>
        /// <para>
        /// The encryption algorithm for signing isn't allowed (signing).
        /// </para>
        /// <para>
        /// In most cases a signature consist of an encrypted
        /// digest of the content.  Therefore a signature algorithm
        /// consists of a digest algorithm and a encryption algorithm.
        /// The encryption algorithm of the signature is not related
        /// to the encryption algorithm of the encryption.
        /// </para>
        /// <para>
        /// For security reasons only the most advanced algorithms are
        /// allowed.  This violation occurs when the encryption algorithm of the 
        /// signature is less advanced then required.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotAllowedSignatureEncryptionAlgorithm,


        /// <summary>
        /// <para>
        /// The subject information should not be trusted (common).
        /// </para>
        /// <para>
        /// The issuer (signing) or receiver (encryption) information failed to
        /// validate. See the <see cref="SecurityInformation.Subject"/> property
        /// for more information.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        UntrustedSubject,

        /// <summary>
        /// <para>
        /// The subject information should not be validated (common).
        /// </para>
        /// <para>
        /// It was impossible to validate the issuer (signing) or receiver (encryption) information. 
        /// See the <see cref="SecurityInformation.Subject"/> property
        /// for more information.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Unsure)]
        [ValidationResult(ValidationStatus.Valid)]
        SubjectTrustUnknown,

        /// <summary>
        /// The inner subject isn't the same as the outer subject.
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        SubjectDoesNotMachEnvelopingSubject,

        /// <summary>
        /// <para>
        /// The time indicated by the message at which it is sealed is not valid.
        /// </para>
        /// <para>
        /// The message includes a time-stamp which which contains a time that doesn't
        /// correspond with the sealing time indicated by the message.  This voids the
        /// trust because the sender is validated on the sealing time that is (incorrectly)
        /// indicated.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        SealingTimeInvalid,

        /// <summary>
        /// The included time-stamp was invalid or could not be trusted.
        /// </summary>
        [TrustLevel(TrustStatus.Unsure)]
        [ValidationResult(ValidationStatus.Valid)]
        InvalidTimestamp,


    }

    /// <summary>
    /// Detailed security information about a certificate (=Subject, Receiver, Issuer, Sender,...).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Certificate are validated on a number of point.  Each of this validation can result in
    /// its own security violation.  See the different member for more information.
    /// </para>
    /// <para>
    /// Each certificate has an issuer.  Security violation of these issues also cause a security
    /// violation on the certificate itself.
    /// </para>
    /// </remarks>
    public enum CertSecurityViolation
    {
        /// <summary>
        /// The issue was invalid. See <see cref="SecurityInformation.Subject"/> property for more information.
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        UntrustedIssuer,

        /// <summary>
        /// The issuer validation was impossible. See <see cref="SecurityInformation.Subject"/> property for more information.
        /// </summary>
        [TrustLevel(TrustStatus.Unsure)]
        [ValidationResult(ValidationStatus.Valid)]
        IssuerTrustUnknown,

        /// <summary>
        /// <para>
        /// The public key in the certificate isn't supported, currently on RSA and DSA are. 
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotValidKeyType,

        /// <summary>
        /// <para>
        /// The size of the key for this certificate is less then the required minimum.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotValidKeySize,

        /// <summary>
        /// <para>
        /// The certificate is not yet or no longer valid at the time of use.
        /// </para>
        /// <para>
        /// For encryption the time is always validated with the current time since
        /// the validation always occurs together with the decryption.  For signing certificates
        /// the signing time is used for validation, is the signing time isn't available
        /// the current time is used.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotTimeValid,


        /// <summary>
        /// <para>
        /// The certificate is revoked according to the windows revocation mechanism.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        Revoked,

        /// <summary>
        /// <para>
        /// The signature of by certificate by it issuer isn't valid.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotSignatureValid,

        /// <summary>
        /// <para>
        /// The certificate is incorrectly used.
        /// </para>
        /// <para>
        /// This can be either a signing certificate that is used
        /// for encryption or visa versa.  It can also be that a non
        /// CA certificate is used to issue a certificate.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NotValidForUsage,

        /// <summary>
        /// <para>
        /// The root certificate could not be found in the trusted CA certificate store of you machine.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Invalid)]
        UntrustedRoot,

        /// <summary>
        /// <para>
        /// The revocation status of the certificate could not be determined.
        /// </para>
        /// <para>
        /// When the certificate contains revocation information windows recognizes
        /// but windows can't retrieve it, this violation is raised.  By default windows
        /// only supports CRLs.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Unsure)]
        RevocationStatusUnknown,

        /// <summary>
        /// <para>
        /// The certificate chain is cyclic.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Unsure)]
        [ValidationResult(ValidationStatus.Invalid)]
        Cyclic,

        /// <summary>
        /// The certificate contains an invalid extension.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        InvalidExtension,

        /// <summary>
        /// The certificate violates a policy constraint.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        InvalidPolicyConstraints,

        /// <summary>
        /// the certificate violates a basic constraint.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        InvalidBasicConstraints,

        /// <summary>
        /// The certificate violates a name constraint.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        InvalidNameConstraints,

        /// <summary>
        /// The certificate contains a name constraint that can't be validated by windows.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Unsure)]
        HasNotSupportedNameConstraint,

        /// <summary>
        /// The certificates violates a name constraint because its name wasn't defined.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        HasNotDefinedNameConstraint,

        /// <summary>
        /// The certificates violates a name constraint because its name is explicitly not permitted.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        HasNotPermittedNameConstraint,

        /// <summary>
        /// The certificates violates a name constraint because its name is excluded.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        HasExcludedNameConstraint,

        /// <summary>
        /// <para>
        /// The revocation information used was cached.
        /// </para>
        /// <para>
        /// CRLs, which are used for revocation, have a certain validity period a can
        /// therefore be cached.  The "violation" only indicates a cached version is used,
        /// this does not mean the certificate is invalid.
        /// </para>
        /// <para>
        /// If you application does not allow off-line revocation, you must explicitly 
        /// check the validation result.
        /// </para>
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Valid)]
        OfflineRevocation,

        /// <summary>
        /// Specifies that there is no certificate policy extension in the certificate. This error would occur if a group policy has specified that all certificates must have a certificate policy.
        /// </summary>
        [TrustLevel(TrustStatus.Full)]
        [ValidationResult(ValidationStatus.Invalid)]
        NoIssuanceChainPolicy,

        /// <summary>
        /// Specifies that the CRL or OCSP has an invalid signature.
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        CtlNotSignatureValid,

        /// <summary>
        /// Specifies that the CRL or OCSP is of the wrong time.
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        CtlNotTimeValid,

        /// <summary>
        /// Specifies that the CRL or OCSP is invalid.
        /// </summary>
        [TrustLevel(TrustStatus.None)]
        [ValidationResult(ValidationStatus.Valid)]
        CtlNotValidForUsage

    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class ValidationResultAttribute : Attribute
    {
        private readonly ValidationStatus result;

        public ValidationStatus Result
        {
            get
            {
                return result;
            }
        }

        public ValidationResultAttribute(ValidationStatus result)
        {
            this.result = result;
        }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class TrustLevelAttribute : Attribute
    {
        private readonly TrustStatus level;

        public TrustStatus Level
        {
            get
            {
                return level;
            }
        }

        public TrustLevelAttribute(TrustStatus level)
        {
            this.level = level;
        }
    }
}
