/*
 *  This file is part of eH-I.
 *  Copyright (C) 2025 Egelke BVBA
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
    /// <summary>
    /// Logs the formatted messages to the provided logger.
    /// </summary>
    public class LoggingMessageInspector : IClientMessageInspector
    {

        XmlWriterSettings _settings;

        private readonly ILogger<LoggingMessageInspector> _logger;

        /// <summary>
        /// Default constructor
        /// </summary>
        /// <param name="logger">The logger to log the message to</param>
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
        
        /// <summary>
        /// Logs the response mesage
        /// </summary>
        /// <param name="reply">the response message to log</param>
        /// <param name="correlationState">correlation state, not used</param>
        public void AfterReceiveReply(ref Message reply, object correlationState)
        {
            var buffer = reply.CreateBufferedCopy(int.MaxValue);
            var copy = buffer.CreateMessage();
            reply = buffer.CreateMessage();

            var xml = MessageToString(copy);
            _logger.LogInformation("SOAP Response:\n{0}", xml);

        }

        /// <summary>
        /// Log the request message
        /// </summary>
        /// <param name="request">the request message to log</param>
        /// <param name="channel">the canneld, not used</param>
        /// <returns>a clone of the request, unaltered</returns>
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
