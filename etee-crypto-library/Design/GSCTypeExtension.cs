using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Markup;

namespace Egelke.EHealth.Etee.Crypto.Wf.Design
{
    [MarkupExtensionReturnType(typeof(Type))]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class GSCTypeExtension : MarkupExtension
    {

        public override Object ProvideValue(IServiceProvider serviceProvider)
        {
            return typeof(ICollection<String>);
        }
    }


}
