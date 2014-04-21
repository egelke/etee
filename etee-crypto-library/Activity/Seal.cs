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

using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Wf.Design;
using System;
using System.Activities;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Drawing;
using System.Drawing.Design;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms.Design;

namespace Egelke.EHealth.Etee.Crypto.Wf.Activity
{
    [Designer(typeof(SealDesigner))]
    [ToolboxBitmap(typeof(SealDesigner))]
    public class Seal : CodeActivity
    {
        [Category("Basic")]
        public InArgument<Wf.Sender> Sender { get; set; }

        [Category("Basic")]
        public InArgument<Wf.Recipients> Recipients { get; set; }

        [Category("Basic")]
        public InArgument<Stream> InMessage { get; set; }

        [Category("Basic")]
        public InArgument<Stream> OutMessage { get; set; }

        [Category("Level")]
        [DefaultValue(ProtectionLevel.LTA_Level)]
        public ProtectionLevel ProtectionLevel { get; set; }

        [Category("Level")]
        [DefaultValue(TrustStatus.Full)]
        public TrustStatus MinimumTokenTrust { get; set; }

        [Category("Level")]
        [DefaultValue(TimeInfoType.TimeMarkAuthority)]
        public TimeInfoType TimeInfoType { get; set; }

        [Category("Services")]
        [DefaultValue("https://services.ehealth.fgov.be/EtkDepot/v1")]
        public Uri TimeStampAuthorityUri { get; set; }

        [Category("Services")]
        [DefaultValue("https://services.ehealth.fgov.be/TimestampAuthority/v2")]
        public Uri EtkDepotUri { get; set; }

        public Seal()
        {
            MinimumTokenTrust = TrustStatus.Full;
            ProtectionLevel = Wf.ProtectionLevel.LTA_Level;
            TimeInfoType = Wf.TimeInfoType.TimeMarkAuthority;
            EtkDepotUri = new Uri("https://services.ehealth.fgov.be/EtkDepot/v1");
            TimeStampAuthorityUri = new Uri("https://services.ehealth.fgov.be/TimestampAuthority/v2");
        }

        protected override void Execute(CodeActivityContext context)
        {
            Wf.Recipients recipients = Recipients.Get(context);
            if (recipients == null) throw new ArgumentNullException("Recipients");

            IDataSealer sealer = CreateDataSealer(context);

            EncryptionToken[] tokens = GetTokens(context, recipients.Addressed);

            using(Stream outMsg = sealer.Seal(InMessage.Get(context), null, tokens))
            {
                Stream destination = OutMessage.Get(context);
                outMsg.CopyTo(destination);
            }
        }

        
        private EncryptionToken[] GetTokens(CodeActivityContext context, List<KnownRecipient> addressed)
        {
            EncryptionToken[] tokens = new EncryptionToken[0];

            var binding = new BasicHttpBinding();
            binding.Security.Mode = BasicHttpSecurityMode.Transport;
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
            ServiceClient.EtkDepotPortTypeClient etkDepotClient = new ServiceClient.EtkDepotPortTypeClient(binding, new EndpointAddress(EtkDepotUri));
            ServiceClient.GetEtkRequest request = new ServiceClient.GetEtkRequest();
            request.SearchCriteria = new ServiceClient.IdentifierType[addressed.Count];
            for (int i = 0; i < addressed.Count; i++)
            {
                request.SearchCriteria[i] = new ServiceClient.IdentifierType();
                request.SearchCriteria[i].Type = addressed[i].Type;
                request.SearchCriteria[i].Value = addressed[i].Value;
                request.SearchCriteria[i].ApplicationID = addressed[i].ApplicationId;
            }

            ServiceClient.GetEtkResponse response = etkDepotClient.GetEtk(request);
            ServiceException.Check(response);

            tokens = new EncryptionToken[response.Items.Length];
            for (int i = 0; i < response.Items.Length; i++)
            {
                byte[] etkRaw = null;
                if (response.Items[i] is ServiceClient.MatchingEtk)
                {
                    StringBuilder builder = new StringBuilder();
                    builder.Append("[");
                    foreach (ServiceClient.IdentifierType id in ((ServiceClient.MatchingEtk)response.Items[i]).Identifier)
                    {
                        builder.Append(id.Type)
                            .Append("=")
                            .Append(id.Value);
                        if (id.ApplicationID != null)
                        {
                            builder.Append(", ")
                                .Append(id.ApplicationID);
                        }
                        builder.Append("; ");
                    }
                    builder.Append("]");
                    throw new InvalidOperationException("The token could not be retrieved, none/multiple tokens match: " + builder.ToString());
                }
                else if (response.Items[i] is byte[])
                {
                    etkRaw = (byte[])response.Items[i];
                }
                tokens[i] = new EncryptionToken(etkRaw);
                CertificateSecurityInformation tokenInfo = tokens[i].Verify();
                if (tokenInfo.ValidationStatus != ValidationStatus.Valid) throw new VerifyException<CertSecurityViolation>(tokenInfo);
                switch (MinimumTokenTrust)
                {
                    case TrustStatus.Full:
                        if (tokenInfo.TrustStatus != TrustStatus.Full) throw new VerifyException<CertSecurityViolation>(tokenInfo);
                        break;
                    case TrustStatus.Unsure:
                        if (tokenInfo.TrustStatus == TrustStatus.None) throw new VerifyException<CertSecurityViolation>(tokenInfo);
                        break;
                    default:
                        break;
                }
            }
            
            return tokens;
        }

        private IDataSealer CreateDataSealer(CodeActivityContext context)
        {
            Level level;
            switch (ProtectionLevel)
            {
                case ProtectionLevel.B_Level:
                    level = Level.B_Level;
                    break;
                case ProtectionLevel.T_Level:
                    level = Level.T_Level;
                    break;
                case ProtectionLevel.LT_Level:
                    level = Level.LT_Level;
                    break;
                case ProtectionLevel.LTA_Level:
                    level = Level.LTA_Level;
                    break;
                default:
                    throw new ArgumentException("Level", "Only levels B, T, LT and LTA are allowed");
            }

            Wf.Sender sender = Sender.Get(context);
            if (sender is Wf.EidSender)
            {
                TimeSpan waitTime = ((Wf.EidSender)sender).WaitTime;

                if ((level & Level.T_Level) != Level.T_Level)
                    return EidDataSealerFactory.Create(level, waitTime);
                switch (TimeInfoType)
                {
                    case Wf.TimeInfoType.TimeMarkAuthority:
                        return EidDataSealerFactory.CreateForTimemarkAuthority(level, waitTime);
                    case Wf.TimeInfoType.TimeStampAuthrity_Rfc3161:
                        return EidDataSealerFactory.Create(level, new Rfc3161TimestampProvider(TimeStampAuthorityUri), waitTime);
                    default:
                        throw new NotImplementedException();
                }
            }

            if (sender is Wf.EHealthP12Sender)
            {
                EHealthP12 p12 = ((Wf.EHealthP12Sender)sender).ToEHealthP12();

                if ((level & Level.T_Level) != Level.T_Level)
                    return EhDataSealerFactory.Create(level, p12);
                switch (TimeInfoType)
                {
                    case Wf.TimeInfoType.TimeMarkAuthority:
                        return EhDataSealerFactory.CreateForTimemarkAuthority(level, p12);
                    case Wf.TimeInfoType.TimeStampAuthrity_Rfc3161:
                        return EhDataSealerFactory.Create(level, new Rfc3161TimestampProvider(TimeStampAuthorityUri), p12);
                    default:
                        throw new NotImplementedException();
                }
            }
            throw new NotImplementedException();
        }
    }
}
