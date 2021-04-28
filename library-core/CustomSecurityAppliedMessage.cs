using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;
using System.Xml;

namespace Egelke.Wcf.Client
{
    public class CustomSecurityAppliedMessage : Message
    {
        private Message _innerMessage;

        public CustomSecurityAppliedMessage(Message innerMessage)
        {
            _innerMessage = innerMessage;
        }

        public override bool IsEmpty
        {
            get
            {
                return _innerMessage.IsEmpty;
            }
        }

        public override bool IsFault
        {
            get { return _innerMessage.IsFault; }
        }

        public override MessageHeaders Headers
        {
            get { return _innerMessage.Headers; }
        }

        public override MessageProperties Properties
        {
            get { return _innerMessage.Properties; }
        }

        public override MessageVersion Version
        {
            get { return _innerMessage.Version; }
        }

        protected override void OnClose()
        {
            base.OnClose();
            _innerMessage.Close();
        }

        protected override void OnWriteStartEnvelope(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteStartEnvelope(writer);
        }

        /*
        protected override void OnWriteStartHeaders(XmlDictionaryWriter writer)
        {
            
            _innerMessage.WriteStartHeaders(writer);
        }
        */

        protected override void OnWriteStartBody(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteStartBody(writer);
        }

        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteBodyContents(writer);
        }

        protected override string OnGetBodyAttribute(string localName, string ns)
        {
            return _innerMessage.GetBodyAttribute(localName, ns);
        }

        /*
        protected override void OnBodyToString(XmlDictionaryWriter writer)
        {
            _innerMessage.BodyToString(writer);
        }
        */

    }
}
