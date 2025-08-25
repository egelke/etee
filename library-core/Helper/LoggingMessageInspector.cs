using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Helper
{
    public class LoggingMessageInspector : IClientMessageInspector
    {

        XmlWriterSettings _settings;

        private readonly ILogger<LoggingMessageInspector> _logger;

        public LoggingMessageInspector(ILogger<LoggingMessageInspector> logger)
        {
            _logger = logger;

            _settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = "  ", // Two spaces
                NewLineOnAttributes = true,
                NewLineHandling = NewLineHandling.Entitize,
                OmitXmlDeclaration = false
            };

        }

        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
            var buffer = reply.CreateBufferedCopy(int.MaxValue);
            var copy = buffer.CreateMessage();
            reply = buffer.CreateMessage();

            var xml = MessageToString(copy);
            _logger.LogInformation("SOAP Response:\n{0}", xml);

        }

        public object BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            var buffer = request.CreateBufferedCopy(int.MaxValue);
            var copy = buffer.CreateMessage();
            request = buffer.CreateMessage(); // Reset original

            var xml = MessageToString(copy);
            _logger.LogInformation("SOAP Request:\n{0}", xml);
            return null;

        }

        private string MessageToString(Message message)
        {
            var ms = new MemoryStream();
            var writer = XmlWriter.Create(ms, _settings);
            message.WriteMessage(writer);
            writer.Flush();
            ms.Position = 0;
            var reader = new StreamReader(ms);
            return reader.ReadToEnd();
        }

    }
}
