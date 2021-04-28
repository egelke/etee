using System;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;

namespace Egelke.Wcf.Client
{
    public class CustomSecurityChannelFactory<TChannel> : IChannelFactory<TChannel>
    {
        private IChannelFactory<TChannel> _innerChannelFactory;

        public CustomSecurityChannelFactory(IChannelFactory<TChannel> innerChannelFactory)
        {
            _innerChannelFactory = innerChannelFactory;
        }

        public T GetProperty<T>() where T : class
        {
            if (typeof(T) == typeof(IChannelFactory<TChannel>))
            {
                return (T)(object)this;
            }

            return _innerChannelFactory.GetProperty<T>();
        }

        public void Open()
        {
            _innerChannelFactory.Open();
        }

        public void Open(TimeSpan timeout)
        {
            _innerChannelFactory.Open(timeout);
        }
        public IAsyncResult BeginOpen(AsyncCallback callback, object state)
        {
            return _innerChannelFactory.BeginOpen(callback, state);
        }

        public IAsyncResult BeginOpen(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannelFactory.BeginOpen(timeout, callback, state);
        }

        public void EndOpen(IAsyncResult result)
        {
            _innerChannelFactory.EndOpen(result);
        }

        public void Close()
        {
            _innerChannelFactory.Close();
        }

        public void Close(TimeSpan timeout)
        {
            _innerChannelFactory.Close(timeout);
        }

        public IAsyncResult BeginClose(AsyncCallback callback, object state)
        {
            return _innerChannelFactory.BeginClose(callback, state);
        }

        public IAsyncResult BeginClose(TimeSpan timeout, AsyncCallback callback, object state)
        {
            return _innerChannelFactory.BeginClose(timeout, callback, state);
        }

        public void EndClose(IAsyncResult result)
        {
            _innerChannelFactory.EndClose(result);
        }

        public void Abort()
        {
            _innerChannelFactory.Abort();
        }

        public CommunicationState State => _innerChannelFactory.State;

        public event EventHandler Closed
        {
            add { _innerChannelFactory.Closed += value; }
            remove { _innerChannelFactory.Closed -= value; }
        }
        public event EventHandler Closing
        {
            add { _innerChannelFactory.Closing += value; }
            remove { _innerChannelFactory.Closing -= value; }
        }
        public event EventHandler Faulted
        {
            add { _innerChannelFactory.Faulted += value; }
            remove { _innerChannelFactory.Faulted -= value; }
        }
        public event EventHandler Opened
        {
            add { _innerChannelFactory.Opened += value; }
            remove { _innerChannelFactory.Opened -= value; }
        }
        public event EventHandler Opening
        {
            add { _innerChannelFactory.Opening += value; }
            remove { _innerChannelFactory.Opening -= value; }
        }

        public TChannel CreateChannel(EndpointAddress to)
        {
            return CreateChannel(to, to.Uri);
        }

        public TChannel CreateChannel(EndpointAddress to, Uri via)
        {
           
            if (typeof(TChannel) == typeof(IRequestChannel))
            {
                return (TChannel)(object)new CustomSecurityRequestChannel(((IChannelFactory<IRequestChannel>)_innerChannelFactory).CreateChannel(to, via), to, via);
            }
            else
            {
                return _innerChannelFactory.CreateChannel(to, via);
            }
        }
    }
}
