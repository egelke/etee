using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Activities;
using System.Drawing;
using Egelke.EHealth.Etee.Crypto.Wf.Design;
using System.ComponentModel;
using System.IO;
using Egelke.EHealth.Etee.Crypto.Status;

namespace Egelke.EHealth.Etee.Crypto.Wf.Activity
{
    [Designer(typeof(UnsealDesigner))]
    [ToolboxBitmap(typeof(UnsealDesigner))]
    public sealed class Unseal : CodeActivity
    {
        [Category("Basic")]
        public InArgument<String[]> SenderPatters { get; set; }

        [Category("Basic")]
        public InArgument<Wf.Receiver> Receiver { get; set; }

        [Category("Basic")]
        public InArgument<Stream> InMessage { get; set; }

        [Category("Basic")]
        public InArgument<Stream> OutMessage { get; set; }

        [Category("Level")]
        [DefaultValue(ProtectionLevel.LTA_Level)]
        public ProtectionLevel ProtectionLevel { get; set; }

        [Category("Level")]
        [DefaultValue(TrustStatus.Full)]
        public TrustStatus MinimumTrust { get; set; }

        [Category("Level")]
        [DefaultValue(TimeInfoType.TimeMarkAuthority)]
        public TimeInfoType TimeInfoType { get; set; }

        [Category("Services")]
        public Uri TimeMarkAuthorityUri { get; set; }

        public Unseal()
        {
            ProtectionLevel = ProtectionLevel.LTA_Level;
            MinimumTrust = TrustStatus.Full;
            TimeInfoType = Wf.TimeInfoType.TimeMarkAuthority;
        }

        protected override void Execute(CodeActivityContext context)
        {

        }
    }
}
