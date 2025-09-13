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

using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Custom WCF Request Channel for eHealth.
    /// </summary>
    public class CustomSecurityRequestChannel : IRequestChannel
    {
        private ILogger _logger;

        private IRequestChannel _innerChannel;

        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="logger">the logger, can be null</param>
        /// <param name="innerChannel">inner channel to write through</param>
        /// <param name="to">destination address</param>
        /// <param name="via">next hop address</param>
        public CustomSecurityRequestChannel(ILogger logger, IRequestChannel innerChannel, EndpointAddress to, Uri via)
        {
            _logger = logger;
            _innerChannel = innerChannel;
            RemoteAddress = to;
            Via = via;
        }

        /// <summary>
        /// Client credentials to use.
        /// </summary>
        public ClientCredentials ClientCredentials { get; set; }

        /// <summary>
        /// WS-Security version to use.
        /// </summary>
        public SecurityVersion MessageSecurityVersion { get; set; }

        /// <summary>
        /// Parts to sign.
        /// </summary>
        public SignParts SignParts { get; set; }

        /// <summary>
        /// Custom configuration to use.
        /// </summary>
        public CustomSecurity Security { get; set; }

        /// <summary>
        /// Final destination.
        /// </summary>
        public EndpointAddress RemoteAddress { get; }

        /// <summary>
        /// Next hop.
        /// </summary>
        public Uri Via { get; }

        
        /// <summary>
        /// Get the requested property.
        /// </summary>
        /// <typeparam name="T">type of the requested property</typeparam>
        /// <returns>the property from the inner channel</returns>
        public T GetProperty<T>() where T : class
        {
            if (typeof(T) == typeof(IRequestChannel))
            {
                return (T)(object)this;
            }

            return _innerChannel.GetProperty<T>();
        }

        /// <summary>
        /// Opens the inner channel.
        /// </summary>
        public void Open()
        {
            _innerChannel.Open();
        }

        /// <summary>
        /// Opens the inner channel.
        /// </summary>
        /// <param name="timeout">provided timeout to respect</param>
        public void Open(TimeSpan timeout)
        {
            _innerChannel.Open(timeout);
        }

        /// <summary>
        /// Opens the inner channel async.
        /// </summary>
        /// <param name="callback">callback when the channel is opened</param>
        /// <param name="state">user provided state parameters for the callback</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginOpen(AsyncCallback callback, object state)
        {
            return _innerChannel.BeginOpen(callback, state);
        }

        /// <summary>
        /// Opens the inner channel async.
        /// </summary>
        /// <param name="timeout">provided timeout to respect</param>
        /// <param name="callback">callback when the channel is opened</param>
        /// <param name="state">user provided state parameters for the callback</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginOpen(timeout, callback, state);
        }

        /// <summary>
        /// Complets the open on the inner channel.
        /// </summary>
        /// <param name="result">the result of hte BeginOpen call</param>
        public void EndOpen(IAsyncResult result)
        {
            _innerChannel.EndOpen(result);
        }

        /// <summary>
        /// Closes the inner channel.
        /// </summary>
        public void Close()
        {
            _innerChannel.Close();
        }

        /// <summary>
        /// Closes the inner channel.
        /// </summary>
        /// <param name="timeout">Timeout to respect</param>
        public void Close(TimeSpan timeout)
        {
            _innerChannel.Close(timeout);
        }

        /// <summary>
        /// Async closes the inner channel.
        /// </summary>
        /// <param name="callback">callback when the channel is closed</param>
        /// <param name="state">user provided state parameters for the callback</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginClose(AsyncCallback callback, object state)
        {
            return _innerChannel.BeginClose(callback, state);
        }

        /// <summary>
        /// Async closes the inner channel.
        /// </summary>
        /// <param name="timeout">provided timeout to respect</param>
        /// <param name="callback">callback when the channel is closed</param>
        /// <param name="state">user provided state parameters for the callback</param>
        /// <returns>async result</returns>
        public IAsyncResult BeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginClose(timeout, callback, state);
        }

        /// <summary>
        /// Completes the close of the inner channel.
        /// </summary>
        /// <param name="result">the result of the BeginClose call</param>
        public void EndClose(IAsyncResult result)
        {
            _innerChannel.EndClose(result);
        }

        /// <summary>
        /// Aborts the inner channel.
        /// </summary>
        public void Abort()
        {
            _innerChannel.Abort();
        }

        /// <summary>
        /// Exposes the inner channel state.
        /// </summary>
        public CommunicationState State => _innerChannel.State;

        /// <summary>
        /// Exposes the inner channel closed event.
        /// </summary>
        public event EventHandler Closed
        {
            add { _innerChannel.Closed += value; }
            remove { _innerChannel.Closed -= value; }
        }

        /// <summary>
        /// Exposes the inner channel closing event.
        /// </summary>
        public event EventHandler Closing
        {
            add { _innerChannel.Closing += value; }
            remove { _innerChannel.Closing -= value; }
        }

        /// <summary>
        /// Exposes the inner channel faulted event.
        /// </summary>
        public event EventHandler Faulted
        {
            add { _innerChannel.Faulted += value; }
            remove { _innerChannel.Faulted -= value; }
        }

        /// <summary>
        /// Exposes the inner channel opened event.
        /// </summary>
        public event EventHandler Opened
        {
            add { _innerChannel.Opened += value; }
            remove { _innerChannel.Opened -= value; }
        }

        /// <summary>
        /// Exposes the inner channel opening event.
        /// </summary>
        public event EventHandler Opening
        {
            add { _innerChannel.Opening += value; }
            remove { _innerChannel.Opening -= value; }
        }

        /// <summary>
        /// Send and Receives the message using the inner channel.
        /// </summary>
        /// <remarks>
        /// Wrap the request so WS-Security can be added at end; verifies the response.
        /// </remarks>
        /// <param name="message">the message to send</param>
        /// <returns>the received response</returns>
        public Message Request(Message message)
        {
            return Verify(_innerChannel.Request(Wrap(message)));
        }

        /// <summary>
        /// Send and Receives the message using the inner channel.
        /// </summary>
        /// <remarks>
        /// Wrap the request so WS-Security can be added at end; verifies the response.
        /// </remarks>
        /// <param name="message">the message to send</param>
        /// <param name="timeout">the timeout to respect</param>
        /// <returns>the received response</returns>
        public Message Request(Message message, TimeSpan timeout)
        {
            return Verify(_innerChannel.Request(Wrap(message), timeout));
        }

        /// <summary>
        /// Send the message using the inner channel asynchrone.
        /// </summary>
        /// <remarks>
        /// Wrap the request so WS-Security can be added at end.
        /// </remarks>
        /// <param name="message">the message to send</param>
        /// <param name="callback">the callback to use when the res</param>
        /// <param name="state">user provided state parameters for the callback</param>
        /// <returns>the async result</returns>
        public IAsyncResult BeginRequest(Message message, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginRequest(Wrap(message), callback, state);
        }

        /// <summary>
        /// Send the message using the inner channel asynchrone.
        /// </summary>
        /// <remarks>
        /// Wrap the request so WS-Security can be added at end.
        /// </remarks>
        /// <param name="message">the message to send</param>
        /// <param name="timeout">the timeout to respect</param>
        /// <param name="callback">the callback to use when the res</param>
        /// <param name="state">user provided state parameters for the callback</param>
        /// <returns>the async result</returns>
        public IAsyncResult BeginRequest(Message message, TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannel.BeginRequest(Wrap(message), timeout, callback, state);
        }

        /// <summary>
        /// Completes the asynchronous reception of the message using the inner channel.
        /// </summary>
        /// <remarks>
        /// Verifies the response.
        /// </remarks>
        /// <param name="result">the result of the Begin Request call</param>
        /// <returns>The receive response</returns>
        public Message EndRequest(IAsyncResult result)
        {
            return Verify(_innerChannel.EndRequest(result));
        }

        private Message Wrap(Message message)
        {
            return new CustomSecurityAppliedMessage(message, _logger)
            {
                ClientCredentials = this.ClientCredentials,
                MessageSecurityVersion = this.MessageSecurityVersion,
                SignParts = this.SignParts,
                RemoteAddress = this.RemoteAddress,
                Security = this.Security
            };
        }

        private Message Verify(Message message)
        {
            if (message != null)
            {
                var wss = WSS.Create(MessageSecurityVersion);
                int i = message.Headers.FindHeader("Security", WSS.SECEXT10_NS);
                if (i >= 0)
                {
                    MessageHeaderInfo sec = message.Headers[i];
                    XmlDictionaryReader headerReader = message.Headers.GetReaderAtHeader(i);

                    var doc = new XmlDocument();
                    var header = (XmlElement) doc.ReadNode(headerReader);

                    wss.VerifyResponse(header);

                    message.Headers.UnderstoodHeaders.Add(sec);
                }
                else
                {
                    //TODO::OK to have unsecure responses?
                }
            }
            return message;
        }
    }
}
