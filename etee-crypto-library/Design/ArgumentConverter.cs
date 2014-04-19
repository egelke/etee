using Microsoft.CSharp.Activities;
using System;
using System.Activities;
using System.Activities.Expressions;
using System.Activities.Presentation.Model;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;

namespace Egelke.EHealth.Etee.Crypto.Wf.Design
{
    public class ArgumentConverter : IValueConverter
    {

        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value == null) return "set via properties";

            ModelItem modelItem = (ModelItem) value;
            var arg = (Argument) modelItem.GetCurrentValue();

            if (arg.Expression is ITextExpression)
            {
                return ((ITextExpression)arg.Expression).ExpressionText;
            }
            else if (arg.Expression is Literal<Stream>)
            {
                return "\"" + (Literal<Stream>)arg.Expression + "\"";
            }
            else
            {
                throw new NotSupportedException(arg.Expression.GetType().ToString());
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value == null) return null;

            var text = (String)value;
            throw new NotSupportedException(targetType.ToString());

            
            /*
            if (targetType == typeof(InArgument<Stream>))
            {
                CSharpValue<Stream> csArgument = new CSharpValue<Stream>(text);
                return new InArgument<Stream>(csArgument);
            }
            else if (targetType == typeof(OutArgument<Stream>))
            {
                Variable<Stream> sVariable = new Variable<Stream>(text);
                return new OutArgument<Stream>();
            }
            else
                throw new NotSupportedException(targetType.ToString());
             */
        }
    }
}
