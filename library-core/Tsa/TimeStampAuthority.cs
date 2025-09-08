/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
 *  Copyright (C) 2012 I.M. vzw
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

using System.Net.Security;
using System.ServiceModel.Description;

namespace Egelke.EHealth.Client.Tsa
{
#pragma warning disable 1591
    /// <summary>
    /// Interface of the TSA client, do not use directly.
    /// </summary>
    [System.ServiceModel.ServiceContract(Namespace = "urn:egelke:tsa", ConfigurationName = "Egelke.EHealth.Client.Pki.TSA")]
    public interface TimeStampAuthority
    {

        // CODEGEN: Generating message contract since the operation stamp is neither RPC nor document wrapped.
        [System.ServiceModel.OperationContract(Action = "", ReplyAction = "*")]
        [System.ServiceModel.XmlSerializerFormat(SupportFaults = true)]
        [System.ServiceModel.ServiceKnownType(typeof(ResponseBaseType))]
        [System.ServiceModel.ServiceKnownType(typeof(DocumentBaseType))]
        [System.ServiceModel.ServiceKnownType(typeof(RequestBaseType))]
        StampResponse Stamp(StampRequest request);
    }

  
    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignRequest : RequestBaseType
    {
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class RequestBaseType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private AnyType optionalInputsField;

        private InputDocuments inputDocumentsField;

        private string requestIDField;

        private string profileField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 0)]
        public AnyType OptionalInputs
        {
            get
            {
                return optionalInputsField;
            }
            set
            {
                optionalInputsField = value;
                RaisePropertyChanged("OptionalInputs");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 1)]
        public InputDocuments InputDocuments
        {
            get
            {
                return inputDocumentsField;
            }
            set
            {
                inputDocumentsField = value;
                RaisePropertyChanged("InputDocuments");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        public string RequestID
        {
            get
            {
                return requestIDField;
            }
            set
            {
                requestIDField = value;
                RaisePropertyChanged("RequestID");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Profile
        {
            get
            {
                return profileField;
            }
            set
            {
                profileField = value;
                RaisePropertyChanged("Profile");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class AnyType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlElement[] anyField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        public System.Xml.XmlElement[] Any
        {
            get
            {
                return anyField;
            }
            set
            {
                anyField = value;
                RaisePropertyChanged("Any");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class ObjectType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlNode[] anyField;

        private string idField;

        private string mimeTypeField;

        private string encodingField;

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return anyField;
            }
            set
            {
                anyField = value;
                RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("Id");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        public string MimeType
        {
            get
            {
                return mimeTypeField;
            }
            set
            {
                mimeTypeField = value;
                RaisePropertyChanged("MimeType");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Encoding
        {
            get
            {
                return encodingField;
            }
            set
            {
                encodingField = value;
                RaisePropertyChanged("Encoding");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SPKIDataType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        [System.Xml.Serialization.XmlElement("SPKISexp", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        public object[] Items
        {
            get
            {
                return itemsField;
            }
            set
            {
                itemsField = value;
                RaisePropertyChanged("Items");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class PGPDataType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private ItemsChoiceType1[] itemsElementNameField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        [System.Xml.Serialization.XmlElement("PGPKeyID", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElement("PGPKeyPacket", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlChoiceIdentifier("ItemsElementName")]
        public object[] Items
        {
            get
            {
                return itemsField;
            }
            set
            {
                itemsField = value;
                RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("ItemsElementName", Order = 1)]
        [System.Xml.Serialization.XmlIgnore()]
        public ItemsChoiceType1[] ItemsElementName
        {
            get
            {
                return itemsElementNameField;
            }
            set
            {
                itemsElementNameField = value;
                RaisePropertyChanged("ItemsElementName");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
    public enum ItemsChoiceType1
    {

        /// <remarks/>
        [System.Xml.Serialization.XmlEnum("##any:")]
        Item,

        /// <remarks/>
        PGPKeyID,

        /// <remarks/>
        PGPKeyPacket,
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class X509IssuerSerialType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string x509IssuerNameField;

        private string x509SerialNumberField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 0)]
        public string X509IssuerName
        {
            get
            {
                return x509IssuerNameField;
            }
            set
            {
                x509IssuerNameField = value;
                RaisePropertyChanged("X509IssuerName");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "integer", Order = 1)]
        public string X509SerialNumber
        {
            get
            {
                return x509SerialNumberField;
            }
            set
            {
                x509SerialNumberField = value;
                RaisePropertyChanged("X509SerialNumber");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class X509DataType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private ItemsChoiceType[] itemsElementNameField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        [System.Xml.Serialization.XmlElement("X509CRL", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElement("X509Certificate", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElement("X509IssuerSerial", typeof(X509IssuerSerialType), Order = 0)]
        [System.Xml.Serialization.XmlElement("X509SKI", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElement("X509SubjectName", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlChoiceIdentifier("ItemsElementName")]
        public object[] Items
        {
            get
            {
                return itemsField;
            }
            set
            {
                itemsField = value;
                RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("ItemsElementName", Order = 1)]
        [System.Xml.Serialization.XmlIgnore()]
        public ItemsChoiceType[] ItemsElementName
        {
            get
            {
                return itemsElementNameField;
            }
            set
            {
                itemsElementNameField = value;
                RaisePropertyChanged("ItemsElementName");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
    public enum ItemsChoiceType
    {

        /// <remarks/>
        [System.Xml.Serialization.XmlEnum("##any:")]
        Item,

        /// <remarks/>
        X509CRL,

        /// <remarks/>
        X509Certificate,

        /// <remarks/>
        X509IssuerSerial,

        /// <remarks/>
        X509SKI,

        /// <remarks/>
        X509SubjectName,
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class RetrievalMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private TransformType[] transformsField;

        private string uRIField;

        private string typeField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArray(Order = 0)]
        [System.Xml.Serialization.XmlArrayItem("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return transformsField;
            }
            set
            {
                transformsField = value;
                RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string URI
        {
            get
            {
                return uRIField;
            }
            set
            {
                uRIField = value;
                RaisePropertyChanged("URI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Type
        {
            get
            {
                return typeField;
            }
            set
            {
                typeField = value;
                RaisePropertyChanged("Type");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class TransformType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private string[] textField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        [System.Xml.Serialization.XmlElement("XPath", typeof(string), Order = 0)]
        public object[] Items
        {
            get
            {
                return itemsField;
            }
            set
            {
                itemsField = value;
                RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        public string[] Text
        {
            get
            {
                return textField;
            }
            set
            {
                textField = value;
                RaisePropertyChanged("Text");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return algorithmField;
            }
            set
            {
                algorithmField = value;
                RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class RSAKeyValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private byte[] modulusField;

        private byte[] exponentField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 0)]
        public byte[] Modulus
        {
            get
            {
                return modulusField;
            }
            set
            {
                modulusField = value;
                RaisePropertyChanged("Modulus");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 1)]
        public byte[] Exponent
        {
            get
            {
                return exponentField;
            }
            set
            {
                exponentField = value;
                RaisePropertyChanged("Exponent");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class DSAKeyValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private byte[] pField;

        private byte[] qField;

        private byte[] gField;

        private byte[] yField;

        private byte[] jField;

        private byte[] seedField;

        private byte[] pgenCounterField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 0)]
        public byte[] P
        {
            get
            {
                return pField;
            }
            set
            {
                pField = value;
                RaisePropertyChanged("P");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 1)]
        public byte[] Q
        {
            get
            {
                return qField;
            }
            set
            {
                qField = value;
                RaisePropertyChanged("Q");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 2)]
        public byte[] G
        {
            get
            {
                return gField;
            }
            set
            {
                gField = value;
                RaisePropertyChanged("G");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 3)]
        public byte[] Y
        {
            get
            {
                return yField;
            }
            set
            {
                yField = value;
                RaisePropertyChanged("Y");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 4)]
        public byte[] J
        {
            get
            {
                return jField;
            }
            set
            {
                jField = value;
                RaisePropertyChanged("J");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 5)]
        public byte[] Seed
        {
            get
            {
                return seedField;
            }
            set
            {
                seedField = value;
                RaisePropertyChanged("Seed");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 6)]
        public byte[] PgenCounter
        {
            get
            {
                return pgenCounterField;
            }
            set
            {
                pgenCounterField = value;
                RaisePropertyChanged("PgenCounter");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class KeyValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object itemField;

        private string[] textField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        [System.Xml.Serialization.XmlElement("DSAKeyValue", typeof(DSAKeyValueType), Order = 0)]
        [System.Xml.Serialization.XmlElement("RSAKeyValue", typeof(RSAKeyValueType), Order = 0)]
        public object Item
        {
            get
            {
                return itemField;
            }
            set
            {
                itemField = value;
                RaisePropertyChanged("Item");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        public string[] Text
        {
            get
            {
                return textField;
            }
            set
            {
                textField = value;
                RaisePropertyChanged("Text");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class KeyInfoType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private ItemsChoiceType2[] itemsElementNameField;

        private string[] textField;

        private string idField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        [System.Xml.Serialization.XmlElement("KeyName", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlElement("KeyValue", typeof(KeyValueType), Order = 0)]
        [System.Xml.Serialization.XmlElement("MgmtData", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlElement("PGPData", typeof(PGPDataType), Order = 0)]
        [System.Xml.Serialization.XmlElement("RetrievalMethod", typeof(RetrievalMethodType), Order = 0)]
        [System.Xml.Serialization.XmlElement("SPKIData", typeof(SPKIDataType), Order = 0)]
        [System.Xml.Serialization.XmlElement("X509Data", typeof(X509DataType), Order = 0)]
        [System.Xml.Serialization.XmlChoiceIdentifier("ItemsElementName")]
        public object[] Items
        {
            get
            {
                return itemsField;
            }
            set
            {
                itemsField = value;
                RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("ItemsElementName", Order = 1)]
        [System.Xml.Serialization.XmlIgnore()]
        public ItemsChoiceType2[] ItemsElementName
        {
            get
            {
                return itemsElementNameField;
            }
            set
            {
                itemsElementNameField = value;
                RaisePropertyChanged("ItemsElementName");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        public string[] Text
        {
            get
            {
                return textField;
            }
            set
            {
                textField = value;
                RaisePropertyChanged("Text");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("Id");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
    public enum ItemsChoiceType2
    {

        /// <remarks/>
        [System.Xml.Serialization.XmlEnum("##any:")]
        Item,

        /// <remarks/>
        KeyName,

        /// <remarks/>
        KeyValue,

        /// <remarks/>
        MgmtData,

        /// <remarks/>
        PGPData,

        /// <remarks/>
        RetrievalMethod,

        /// <remarks/>
        SPKIData,

        /// <remarks/>
        X509Data,
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignatureValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string idField;

        private byte[] valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("Id");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText(DataType = "base64Binary")]
        public byte[] Value
        {
            get
            {
                return valueField;
            }
            set
            {
                valueField = value;
                RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class ReferenceType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private TransformType[] transformsField;

        private DigestMethodType digestMethodField;

        private byte[] digestValueField;

        private string idField;

        private string uRIField;

        private string typeField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArray(Order = 0)]
        [System.Xml.Serialization.XmlArrayItem("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return transformsField;
            }
            set
            {
                transformsField = value;
                RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 1)]
        public DigestMethodType DigestMethod
        {
            get
            {
                return digestMethodField;
            }
            set
            {
                digestMethodField = value;
                RaisePropertyChanged("DigestMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "base64Binary", Order = 2)]
        public byte[] DigestValue
        {
            get
            {
                return digestValueField;
            }
            set
            {
                digestValueField = value;
                RaisePropertyChanged("DigestValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("Id");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string URI
        {
            get
            {
                return uRIField;
            }
            set
            {
                uRIField = value;
                RaisePropertyChanged("URI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Type
        {
            get
            {
                return typeField;
            }
            set
            {
                typeField = value;
                RaisePropertyChanged("Type");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class DigestMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlNode[] anyField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return anyField;
            }
            set
            {
                anyField = value;
                RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return algorithmField;
            }
            set
            {
                algorithmField = value;
                RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignatureMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string hMACOutputLengthField;

        private System.Xml.XmlNode[] anyField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "integer", Order = 0)]
        public string HMACOutputLength
        {
            get
            {
                return hMACOutputLengthField;
            }
            set
            {
                hMACOutputLengthField = value;
                RaisePropertyChanged("HMACOutputLength");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        [System.Xml.Serialization.XmlAnyElement(Order = 1)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return anyField;
            }
            set
            {
                anyField = value;
                RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return algorithmField;
            }
            set
            {
                algorithmField = value;
                RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class CanonicalizationMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlNode[] anyField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return anyField;
            }
            set
            {
                anyField = value;
                RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return algorithmField;
            }
            set
            {
                algorithmField = value;
                RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignedInfoType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private CanonicalizationMethodType canonicalizationMethodField;

        private SignatureMethodType signatureMethodField;

        private ReferenceType[] referenceField;

        private string idField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 0)]
        public CanonicalizationMethodType CanonicalizationMethod
        {
            get
            {
                return canonicalizationMethodField;
            }
            set
            {
                canonicalizationMethodField = value;
                RaisePropertyChanged("CanonicalizationMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 1)]
        public SignatureMethodType SignatureMethod
        {
            get
            {
                return signatureMethodField;
            }
            set
            {
                signatureMethodField = value;
                RaisePropertyChanged("SignatureMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("Reference", Order = 2)]
        public ReferenceType[] Reference
        {
            get
            {
                return referenceField;
            }
            set
            {
                referenceField = value;
                RaisePropertyChanged("Reference");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("Id");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignatureType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private SignedInfoType signedInfoField;

        private SignatureValueType signatureValueField;

        private KeyInfoType keyInfoField;

        private ObjectType[] objectField;

        private string idField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 0)]
        public SignedInfoType SignedInfo
        {
            get
            {
                return signedInfoField;
            }
            set
            {
                signedInfoField = value;
                RaisePropertyChanged("SignedInfo");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 1)]
        public SignatureValueType SignatureValue
        {
            get
            {
                return signatureValueField;
            }
            set
            {
                signatureValueField = value;
                RaisePropertyChanged("SignatureValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 2)]
        public KeyInfoType KeyInfo
        {
            get
            {
                return keyInfoField;
            }
            set
            {
                keyInfoField = value;
                RaisePropertyChanged("KeyInfo");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("Object", Order = 3)]
        public ObjectType[] Object
        {
            get
            {
                return objectField;
            }
            set
            {
                objectField = value;
                RaisePropertyChanged("Object");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("Id");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class InternationalStringType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string langField;

        private string valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(Form = System.Xml.Schema.XmlSchemaForm.Qualified, Namespace = "http://www.w3.org/XML/1998/namespace")]
        public string lang
        {
            get
            {
                return langField;
            }
            set
            {
                langField = value;
                RaisePropertyChanged("lang");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText()]
        public string Value
        {
            get
            {
                return valueField;
            }
            set
            {
                valueField = value;
                RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class ResponseBaseType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private Result resultField;

        private AnyType optionalOutputsField;

        private string requestIDField;

        private string profileField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 0)]
        public Result Result
        {
            get
            {
                return resultField;
            }
            set
            {
                resultField = value;
                RaisePropertyChanged("Result");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 1)]
        public AnyType OptionalOutputs
        {
            get
            {
                return optionalOutputsField;
            }
            set
            {
                optionalOutputsField = value;
                RaisePropertyChanged("OptionalOutputs");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        public string RequestID
        {
            get
            {
                return requestIDField;
            }
            set
            {
                requestIDField = value;
                RaisePropertyChanged("RequestID");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Profile
        {
            get
            {
                return profileField;
            }
            set
            {
                profileField = value;
                RaisePropertyChanged("Profile");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Result : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string resultMajorField;

        private string resultMinorField;

        private InternationalStringType resultMessageField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "anyURI", Order = 0)]
        public string ResultMajor
        {
            get
            {
                return resultMajorField;
            }
            set
            {
                resultMajorField = value;
                RaisePropertyChanged("ResultMajor");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(DataType = "anyURI", Order = 1)]
        public string ResultMinor
        {
            get
            {
                return resultMinorField;
            }
            set
            {
                resultMinorField = value;
                RaisePropertyChanged("ResultMinor");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 2)]
        public InternationalStringType ResultMessage
        {
            get
            {
                return resultMessageField;
            }
            set
            {
                resultMessageField = value;
                RaisePropertyChanged("ResultMessage");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class AttachmentReferenceType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private DigestMethodType digestMethodField;

        private byte[] digestValueField;

        private string attRefURIField;

        private string mimeTypeField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        public DigestMethodType DigestMethod
        {
            get
            {
                return digestMethodField;
            }
            set
            {
                digestMethodField = value;
                RaisePropertyChanged("DigestMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Namespace = "http://www.w3.org/2000/09/xmldsig#", DataType = "base64Binary", Order = 1)]
        public byte[] DigestValue
        {
            get
            {
                return digestValueField;
            }
            set
            {
                digestValueField = value;
                RaisePropertyChanged("DigestValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string AttRefURI
        {
            get
            {
                return attRefURIField;
            }
            set
            {
                attRefURIField = value;
                RaisePropertyChanged("AttRefURI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        public string MimeType
        {
            get
            {
                return mimeTypeField;
            }
            set
            {
                mimeTypeField = value;
                RaisePropertyChanged("MimeType");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class InlineXMLType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlElement anyField;

        private bool ignorePIsField;

        private bool ignoreCommentsField;

        public InlineXMLType()
        {
            ignorePIsField = true;
            ignoreCommentsField = true;
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElement(Order = 0)]
        public System.Xml.XmlElement Any
        {
            get
            {
                return anyField;
            }
            set
            {
                anyField = value;
                RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        [System.ComponentModel.DefaultValue(true)]
        public bool ignorePIs
        {
            get
            {
                return ignorePIsField;
            }
            set
            {
                ignorePIsField = value;
                RaisePropertyChanged("ignorePIs");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        [System.ComponentModel.DefaultValue(true)]
        public bool ignoreComments
        {
            get
            {
                return ignoreCommentsField;
            }
            set
            {
                ignoreCommentsField = value;
                RaisePropertyChanged("ignoreComments");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Xml.Serialization.XmlInclude(typeof(DocumentType))]
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public abstract partial class DocumentBaseType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string idField;

        private string refURIField;

        private string refTypeField;

        private string schemaRefsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "ID")]
        public string ID
        {
            get
            {
                return idField;
            }
            set
            {
                idField = value;
                RaisePropertyChanged("ID");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string RefURI
        {
            get
            {
                return refURIField;
            }
            set
            {
                refURIField = value;
                RaisePropertyChanged("RefURI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string RefType
        {
            get
            {
                return refTypeField;
            }
            set
            {
                refTypeField = value;
                RaisePropertyChanged("RefType");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "IDREFS")]
        public string SchemaRefs
        {
            get
            {
                return schemaRefsField;
            }
            set
            {
                schemaRefsField = value;
                RaisePropertyChanged("SchemaRefs");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class DocumentType : DocumentBaseType
    {

        private object itemField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("AttachmentReference", typeof(AttachmentReferenceType), Order = 0)]
        [System.Xml.Serialization.XmlElement("Base64Data", typeof(Base64Data), Order = 0)]
        [System.Xml.Serialization.XmlElement("Base64XML", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElement("EscapedXML", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlElement("InlineXML", typeof(InlineXMLType), Order = 0)]
        public object Item
        {
            get
            {
                return itemField;
            }
            set
            {
                itemField = value;
                RaisePropertyChanged("Item");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Base64Data : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string mimeTypeField;

        private byte[] valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        public string MimeType
        {
            get
            {
                return mimeTypeField;
            }
            set
            {
                mimeTypeField = value;
                RaisePropertyChanged("MimeType");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText(DataType = "base64Binary")]
        public byte[] Value
        {
            get
            {
                return valueField;
            }
            set
            {
                valueField = value;
                RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class InputDocuments : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("Document", typeof(DocumentType), Order = 0)]
        [System.Xml.Serialization.XmlElement("DocumentHash", typeof(DocumentHash), Order = 0)]
        [System.Xml.Serialization.XmlElement("Other", typeof(AnyType), Order = 0)]
        [System.Xml.Serialization.XmlElement("TransformedData", typeof(TransformedData), Order = 0)]
        public object[] Items
        {
            get
            {
                return itemsField;
            }
            set
            {
                itemsField = value;
                RaisePropertyChanged("Items");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class DocumentHash : DocumentBaseType
    {

        private TransformType[] transformsField;

        private DigestMethodType digestMethodField;

        private byte[] digestValueField;

        private string whichReferenceField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArray(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlArrayItem("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return transformsField;
            }
            set
            {
                transformsField = value;
                RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 1)]
        public DigestMethodType DigestMethod
        {
            get
            {
                return digestMethodField;
            }
            set
            {
                digestMethodField = value;
                RaisePropertyChanged("DigestMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Namespace = "http://www.w3.org/2000/09/xmldsig#", DataType = "base64Binary", Order = 2)]
        public byte[] DigestValue
        {
            get
            {
                return digestValueField;
            }
            set
            {
                digestValueField = value;
                RaisePropertyChanged("DigestValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "integer")]
        public string WhichReference
        {
            get
            {
                return whichReferenceField;
            }
            set
            {
                whichReferenceField = value;
                RaisePropertyChanged("WhichReference");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class TransformedData : DocumentBaseType
    {

        private TransformType[] transformsField;

        private Base64Data base64DataField;

        private string whichReferenceField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArray(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlArrayItem("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return transformsField;
            }
            set
            {
                transformsField = value;
                RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 1)]
        public Base64Data Base64Data
        {
            get
            {
                return base64DataField;
            }
            set
            {
                base64DataField = value;
                RaisePropertyChanged("Base64Data");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "integer")]
        public string WhichReference
        {
            get
            {
                return whichReferenceField;
            }
            set
            {
                whichReferenceField = value;
                RaisePropertyChanged("WhichReference");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignResponse : ResponseBaseType
    {

        private SignatureObject signatureObjectField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(Order = 0)]
        public SignatureObject SignatureObject
        {
            get
            {
                return signatureObjectField;
            }
            set
            {
                signatureObjectField = value;
                RaisePropertyChanged("SignatureObject");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignatureObject : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object itemField;

        private string schemaRefsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("Signature", typeof(SignatureType), Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlElement("Base64Signature", typeof(Base64Signature), Order = 0)]
        [System.Xml.Serialization.XmlElement("Other", typeof(AnyType), Order = 0)]
        [System.Xml.Serialization.XmlElement("SignaturePtr", typeof(SignaturePtr), Order = 0)]
        [System.Xml.Serialization.XmlElement("Timestamp", typeof(Timestamp), Order = 0)]
        public object Item
        {
            get
            {
                return itemField;
            }
            set
            {
                itemField = value;
                RaisePropertyChanged("Item");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "IDREFS")]
        public string SchemaRefs
        {
            get
            {
                return schemaRefsField;
            }
            set
            {
                schemaRefsField = value;
                RaisePropertyChanged("SchemaRefs");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>ute()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Base64Signature : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string typeField;

        private byte[] valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "anyURI")]
        public string Type
        {
            get
            {
                return typeField;
            }
            set
            {
                typeField = value;
                RaisePropertyChanged("Type");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlText(DataType = "base64Binary")]
        public byte[] Value
        {
            get
            {
                return valueField;
            }
            set
            {
                valueField = value;
                RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignaturePtr : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string whichDocumentField;

        private string xPathField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute(DataType = "IDREF")]
        public string WhichDocument
        {
            get
            {
                return whichDocumentField;
            }
            set
            {
                whichDocumentField = value;
                RaisePropertyChanged("WhichDocument");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttribute()]
        public string XPath
        {
            get
            {
                return xPathField;
            }
            set
            {
                xPathField = value;
                RaisePropertyChanged("XPath");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Serializable()]
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.DesignerCategory("code")]
    [System.Xml.Serialization.XmlType(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Timestamp : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object itemField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElement("Signature", typeof(SignatureType), Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlElement("Other", typeof(AnyType), Order = 0)]
        [System.Xml.Serialization.XmlElement("RFC3161TimeStampToken", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        public object Item
        {
            get
            {
                return itemField;
            }
            set
            {
                itemField = value;
                RaisePropertyChanged("Item");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = PropertyChanged;
            if (propertyChanged != null)
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContract(IsWrapped = false)]
    public partial class StampRequest
    {

        [System.ServiceModel.MessageBodyMember(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema", Order = 0)]
        public SignRequest SignRequest;

        public StampRequest()
        {
        }

        public StampRequest(SignRequest SignRequest)
        {
            this.SignRequest = SignRequest;
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Diagnostics.DebuggerStepThrough()]
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContract(IsWrapped = false)]
    public partial class StampResponse
    {

        [System.ServiceModel.MessageBodyMember(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema", Order = 0)]
        public SignResponse SignResponse;

        public StampResponse()
        {
        }

        public StampResponse(SignResponse SignResponse)
        {
            this.SignResponse = SignResponse;
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    public interface TimeStampAuthorityChannel : TimeStampAuthority, System.ServiceModel.IClientChannel
    {
    }

    /// <summary>
    /// TSA client, use to specify and configure the TSA via code.
    /// </summary>
    [System.Diagnostics.DebuggerStepThrough()]
    public partial class TimeStampAuthorityClient : System.ServiceModel.ClientBase<TimeStampAuthority>, TimeStampAuthority
    {

        /// <summary>
        /// Use the configuration with name "Xades.TSA" from the application config 
        /// </summary>
        public TimeStampAuthorityClient()
        {
        }

        /// <summary>
        /// Uses the configuration with the provided name from the application config.
        /// </summary>
        /// <param name="endpoint">The configuration of the endpoint</param>
        public TimeStampAuthorityClient(ServiceEndpoint endpoint) :
            base(endpoint)
        {
        }

        /// <summary>
        /// Uses the provided binding and address, does not uses the application config.
        /// </summary>
        /// <param name="binding">The pre-configured binding</param>
        /// <param name="remoteAddress">The address of the TSA</param>
        public TimeStampAuthorityClient(System.ServiceModel.Channels.Binding binding, System.ServiceModel.EndpointAddress remoteAddress) :
            base(binding, remoteAddress)
        {
        }

        [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Advanced)]
        StampResponse TimeStampAuthority.Stamp(StampRequest request)
        {
            return Channel.Stamp(request);
        }

        /// <summary>
        /// Method used by the library, do not call.
        /// </summary>
        public SignResponse Stamp(SignRequest SignRequest)
        {
            StampRequest inValue = new StampRequest();
            inValue.SignRequest = SignRequest;
            StampResponse retVal = ((TimeStampAuthority)this).Stamp(inValue);
            return retVal.SignResponse;
        }
    }
#pragma warning restore 1591
}