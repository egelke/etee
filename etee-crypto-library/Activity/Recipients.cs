using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Activities;
using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using Egelke.EHealth.Etee.Crypto.Wf.Design;

namespace Egelke.EHealth.Etee.Crypto.Wf.Activity
{

    [Designer(typeof(RecipientsDesigner))]
    public sealed class Recipients : CodeActivity
    {
        private const string AddressedRegEx = "(?<type>.*)=(?<value>\\d*)(, (?<app>\\w+))?";
        private const string UnaddressedRegEx = "[{](?<ns>.*)[}](?<name>.*)=(?<value>.*)";

        public OutArgument<Wf.Recipients> To { get; set; }

        public InArgument<ICollection<String>> Addressed { get; set; }

        public InArgument<ICollection<String>> UnaddressedAllowed { get; set; }

        public InArgument<ICollection<String>> UnaddressedExcluded { get; set; }

        protected override void Execute(CodeActivityContext context)
        {
            var recipients = new Wf.Recipients();

            ICollection<String> addressed = Addressed.Get(context);
            if (addressed != null)
            {
                Regex regex = new Regex(AddressedRegEx);
                foreach (String address in addressed)
                {
                    MatchCollection matches = regex.Matches(address);
                    if (matches.Count != 1) new ArgumentException("In Argument Addressed contains an invalid address: " + address);

                    var recipient = new KnownRecipient();
                    recipient.Type = matches[0].Groups["type"].Value;
                    recipient.Value = matches[0].Groups["value"].Value;
                    recipient.ApplicationId = matches[0].Groups["app"].Success ? matches[0].Groups["app"].Value : null;
                    recipients.Addressed.Add(recipient);
                }
            }
            ICollection<String> unaddressedAllowed = UnaddressedAllowed.Get(context);
            if (unaddressedAllowed != null)
            {
                Regex regex = new Regex(UnaddressedRegEx);
                foreach(String allowed in unaddressedAllowed)
                {
                    MatchCollection matches = regex.Matches(allowed);
                    if (matches.Count != 1) new ArgumentException("In Argument UnaddressedAllowed contains an invalid address: " + allowed);

                    var recipient = new UnknownRecipient();
                    recipient.Namespace = matches[0].Groups["ns"].Value;
                    recipient.Name = matches[0].Groups["name"].Value;
                    recipient.Value = matches[0].Groups["value"].Value;
                    recipients.Unaddressed.Allowed.Add(recipient);
                }
                ICollection<String> unaddressedExcluded = UnaddressedExcluded.Get(context);
                if (unaddressedExcluded != null)
                {
                    foreach (String excluded in unaddressedExcluded)
                    {
                        MatchCollection matches = regex.Matches(excluded);
                        if (matches.Count != 1) new ArgumentException("In Argument UnaddressedExcluded contains an invalid address: " + excluded);

                        var recipient = new UnknownRecipient();
                        recipient.Namespace = matches[0].Groups["ns"].Value;
                        recipient.Name = matches[0].Groups["name"].Value;
                        recipient.Value = matches[0].Groups["value"].Value;
                        recipients.Unaddressed.Excluded.Add(recipient);
                    }
                }
            }

            To.Set(context, recipients);
        }
    }
}
