using Microsoft.Extensions.Logging;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

#if NETFRAMEWORK
using Microsoft.Extensions.Logging.TraceSource;
#endif

namespace Egelke.Wcf.Client.Helper
{
    internal class TraceLogger
    {
        public static ILogger CreateTraceLogger<T>()
        {
#if NETFRAMEWORK
            var trace = new TraceSource("Egelke.Wcf.Client");
            var traceLogProv = new TraceSourceLoggerProvider(trace.Switch);
            return traceLogProv.CreateLogger(typeof(T).FullName);
#else
            return null;
#endif
        }
    }
}
