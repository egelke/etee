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

namespace Egelke.EHealth.Client.Pki.DSS
{
#pragma warning disable 1591
    /// <summary>
    /// Interface of the TSA client, do not use directly.
    /// </summary>
    [System.ServiceModel.ServiceContractAttribute(ProtectionLevel = ProtectionLevel.Sign, Namespace = "urn:egelke:xades:tsa", ConfigurationName = "Xades.TSA")]
    public interface TimeStampAuthority
    {

        // CODEGEN: Generating message contract since the operation stamp is neither RPC nor document wrapped.
        [System.ServiceModel.OperationContractAttribute(Action = "", ReplyAction = "*")]
        [System.ServiceModel.XmlSerializerFormatAttribute(SupportFaults = true)]
        [System.ServiceModel.ServiceKnownTypeAttribute(typeof(ResponseBaseType))]
        [System.ServiceModel.ServiceKnownTypeAttribute(typeof(DocumentBaseType))]
        [System.ServiceModel.ServiceKnownTypeAttribute(typeof(RequestBaseType))]
        StampResponse Stamp(StampRequest request);
    }

  
    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignRequest : RequestBaseType
    {
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class RequestBaseType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private AnyType optionalInputsField;

        private InputDocuments inputDocumentsField;

        private string requestIDField;

        private string profileField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public AnyType OptionalInputs
        {
            get
            {
                return this.optionalInputsField;
            }
            set
            {
                this.optionalInputsField = value;
                this.RaisePropertyChanged("OptionalInputs");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public InputDocuments InputDocuments
        {
            get
            {
                return this.inputDocumentsField;
            }
            set
            {
                this.inputDocumentsField = value;
                this.RaisePropertyChanged("InputDocuments");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string RequestID
        {
            get
            {
                return this.requestIDField;
            }
            set
            {
                this.requestIDField = value;
                this.RaisePropertyChanged("RequestID");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Profile
        {
            get
            {
                return this.profileField;
            }
            set
            {
                this.profileField = value;
                this.RaisePropertyChanged("Profile");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class AnyType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlElement[] anyField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlElement[] Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
                this.RaisePropertyChanged("Any");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class ObjectType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlNode[] anyField;

        private string idField;

        private string mimeTypeField;

        private string encodingField;

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
                this.RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("Id");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string MimeType
        {
            get
            {
                return this.mimeTypeField;
            }
            set
            {
                this.mimeTypeField = value;
                this.RaisePropertyChanged("MimeType");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Encoding
        {
            get
            {
                return this.encodingField;
            }
            set
            {
                this.encodingField = value;
                this.RaisePropertyChanged("Encoding");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SPKIDataType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("SPKISexp", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        public object[] Items
        {
            get
            {
                return this.itemsField;
            }
            set
            {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class PGPDataType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private ItemsChoiceType1[] itemsElementNameField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("PGPKeyID", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("PGPKeyPacket", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlChoiceIdentifierAttribute("ItemsElementName")]
        public object[] Items
        {
            get
            {
                return this.itemsField;
            }
            set
            {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("ItemsElementName", Order = 1)]
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public ItemsChoiceType1[] ItemsElementName
        {
            get
            {
                return this.itemsElementNameField;
            }
            set
            {
                this.itemsElementNameField = value;
                this.RaisePropertyChanged("ItemsElementName");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
    public enum ItemsChoiceType1
    {

        /// <remarks/>
        [System.Xml.Serialization.XmlEnumAttribute("##any:")]
        Item,

        /// <remarks/>
        PGPKeyID,

        /// <remarks/>
        PGPKeyPacket,
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class X509IssuerSerialType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string x509IssuerNameField;

        private string x509SerialNumberField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public string X509IssuerName
        {
            get
            {
                return this.x509IssuerNameField;
            }
            set
            {
                this.x509IssuerNameField = value;
                this.RaisePropertyChanged("X509IssuerName");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "integer", Order = 1)]
        public string X509SerialNumber
        {
            get
            {
                return this.x509SerialNumberField;
            }
            set
            {
                this.x509SerialNumberField = value;
                this.RaisePropertyChanged("X509SerialNumber");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class X509DataType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private ItemsChoiceType[] itemsElementNameField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("X509CRL", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("X509Certificate", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("X509IssuerSerial", typeof(X509IssuerSerialType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("X509SKI", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("X509SubjectName", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlChoiceIdentifierAttribute("ItemsElementName")]
        public object[] Items
        {
            get
            {
                return this.itemsField;
            }
            set
            {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("ItemsElementName", Order = 1)]
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public ItemsChoiceType[] ItemsElementName
        {
            get
            {
                return this.itemsElementNameField;
            }
            set
            {
                this.itemsElementNameField = value;
                this.RaisePropertyChanged("ItemsElementName");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
    public enum ItemsChoiceType
    {

        /// <remarks/>
        [System.Xml.Serialization.XmlEnumAttribute("##any:")]
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
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class RetrievalMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private TransformType[] transformsField;

        private string uRIField;

        private string typeField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArrayAttribute(Order = 0)]
        [System.Xml.Serialization.XmlArrayItemAttribute("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return this.transformsField;
            }
            set
            {
                this.transformsField = value;
                this.RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string URI
        {
            get
            {
                return this.uRIField;
            }
            set
            {
                this.uRIField = value;
                this.RaisePropertyChanged("URI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Type
        {
            get
            {
                return this.typeField;
            }
            set
            {
                this.typeField = value;
                this.RaisePropertyChanged("Type");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class TransformType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private string[] textField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("XPath", typeof(string), Order = 0)]
        public object[] Items
        {
            get
            {
                return this.itemsField;
            }
            set
            {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string[] Text
        {
            get
            {
                return this.textField;
            }
            set
            {
                this.textField = value;
                this.RaisePropertyChanged("Text");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return this.algorithmField;
            }
            set
            {
                this.algorithmField = value;
                this.RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class RSAKeyValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private byte[] modulusField;

        private byte[] exponentField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 0)]
        public byte[] Modulus
        {
            get
            {
                return this.modulusField;
            }
            set
            {
                this.modulusField = value;
                this.RaisePropertyChanged("Modulus");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 1)]
        public byte[] Exponent
        {
            get
            {
                return this.exponentField;
            }
            set
            {
                this.exponentField = value;
                this.RaisePropertyChanged("Exponent");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
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
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 0)]
        public byte[] P
        {
            get
            {
                return this.pField;
            }
            set
            {
                this.pField = value;
                this.RaisePropertyChanged("P");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 1)]
        public byte[] Q
        {
            get
            {
                return this.qField;
            }
            set
            {
                this.qField = value;
                this.RaisePropertyChanged("Q");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 2)]
        public byte[] G
        {
            get
            {
                return this.gField;
            }
            set
            {
                this.gField = value;
                this.RaisePropertyChanged("G");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 3)]
        public byte[] Y
        {
            get
            {
                return this.yField;
            }
            set
            {
                this.yField = value;
                this.RaisePropertyChanged("Y");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 4)]
        public byte[] J
        {
            get
            {
                return this.jField;
            }
            set
            {
                this.jField = value;
                this.RaisePropertyChanged("J");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 5)]
        public byte[] Seed
        {
            get
            {
                return this.seedField;
            }
            set
            {
                this.seedField = value;
                this.RaisePropertyChanged("Seed");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 6)]
        public byte[] PgenCounter
        {
            get
            {
                return this.pgenCounterField;
            }
            set
            {
                this.pgenCounterField = value;
                this.RaisePropertyChanged("PgenCounter");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class KeyValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object itemField;

        private string[] textField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("DSAKeyValue", typeof(DSAKeyValueType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("RSAKeyValue", typeof(RSAKeyValueType), Order = 0)]
        public object Item
        {
            get
            {
                return this.itemField;
            }
            set
            {
                this.itemField = value;
                this.RaisePropertyChanged("Item");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string[] Text
        {
            get
            {
                return this.textField;
            }
            set
            {
                this.textField = value;
                this.RaisePropertyChanged("Text");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class KeyInfoType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        private ItemsChoiceType2[] itemsElementNameField;

        private string[] textField;

        private string idField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("KeyName", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("KeyValue", typeof(KeyValueType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("MgmtData", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("PGPData", typeof(PGPDataType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("RetrievalMethod", typeof(RetrievalMethodType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("SPKIData", typeof(SPKIDataType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("X509Data", typeof(X509DataType), Order = 0)]
        [System.Xml.Serialization.XmlChoiceIdentifierAttribute("ItemsElementName")]
        public object[] Items
        {
            get
            {
                return this.itemsField;
            }
            set
            {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("ItemsElementName", Order = 1)]
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public ItemsChoiceType2[] ItemsElementName
        {
            get
            {
                return this.itemsElementNameField;
            }
            set
            {
                this.itemsElementNameField = value;
                this.RaisePropertyChanged("ItemsElementName");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string[] Text
        {
            get
            {
                return this.textField;
            }
            set
            {
                this.textField = value;
                this.RaisePropertyChanged("Text");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("Id");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", IncludeInSchema = false)]
    public enum ItemsChoiceType2
    {

        /// <remarks/>
        [System.Xml.Serialization.XmlEnumAttribute("##any:")]
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
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignatureValueType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string idField;

        private byte[] valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("Id");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute(DataType = "base64Binary")]
        public byte[] Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
                this.RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class ReferenceType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private TransformType[] transformsField;

        private DigestMethodType digestMethodField;

        private byte[] digestValueField;

        private string idField;

        private string uRIField;

        private string typeField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArrayAttribute(Order = 0)]
        [System.Xml.Serialization.XmlArrayItemAttribute("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return this.transformsField;
            }
            set
            {
                this.transformsField = value;
                this.RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public DigestMethodType DigestMethod
        {
            get
            {
                return this.digestMethodField;
            }
            set
            {
                this.digestMethodField = value;
                this.RaisePropertyChanged("DigestMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "base64Binary", Order = 2)]
        public byte[] DigestValue
        {
            get
            {
                return this.digestValueField;
            }
            set
            {
                this.digestValueField = value;
                this.RaisePropertyChanged("DigestValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("Id");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string URI
        {
            get
            {
                return this.uRIField;
            }
            set
            {
                this.uRIField = value;
                this.RaisePropertyChanged("URI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Type
        {
            get
            {
                return this.typeField;
            }
            set
            {
                this.typeField = value;
                this.RaisePropertyChanged("Type");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class DigestMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlNode[] anyField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
                this.RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return this.algorithmField;
            }
            set
            {
                this.algorithmField = value;
                this.RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignatureMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string hMACOutputLengthField;

        private System.Xml.XmlNode[] anyField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "integer", Order = 0)]
        public string HMACOutputLength
        {
            get
            {
                return this.hMACOutputLengthField;
            }
            set
            {
                this.hMACOutputLengthField = value;
                this.RaisePropertyChanged("HMACOutputLength");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 1)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
                this.RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return this.algorithmField;
            }
            set
            {
                this.algorithmField = value;
                this.RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class CanonicalizationMethodType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlNode[] anyField;

        private string algorithmField;

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlNode[] Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
                this.RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Algorithm
        {
            get
            {
                return this.algorithmField;
            }
            set
            {
                this.algorithmField = value;
                this.RaisePropertyChanged("Algorithm");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignedInfoType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private CanonicalizationMethodType canonicalizationMethodField;

        private SignatureMethodType signatureMethodField;

        private ReferenceType[] referenceField;

        private string idField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public CanonicalizationMethodType CanonicalizationMethod
        {
            get
            {
                return this.canonicalizationMethodField;
            }
            set
            {
                this.canonicalizationMethodField = value;
                this.RaisePropertyChanged("CanonicalizationMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public SignatureMethodType SignatureMethod
        {
            get
            {
                return this.signatureMethodField;
            }
            set
            {
                this.signatureMethodField = value;
                this.RaisePropertyChanged("SignatureMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Reference", Order = 2)]
        public ReferenceType[] Reference
        {
            get
            {
                return this.referenceField;
            }
            set
            {
                this.referenceField = value;
                this.RaisePropertyChanged("Reference");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("Id");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#")]
    public partial class SignatureType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private SignedInfoType signedInfoField;

        private SignatureValueType signatureValueField;

        private KeyInfoType keyInfoField;

        private ObjectType[] objectField;

        private string idField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public SignedInfoType SignedInfo
        {
            get
            {
                return this.signedInfoField;
            }
            set
            {
                this.signedInfoField = value;
                this.RaisePropertyChanged("SignedInfo");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public SignatureValueType SignatureValue
        {
            get
            {
                return this.signatureValueField;
            }
            set
            {
                this.signatureValueField = value;
                this.RaisePropertyChanged("SignatureValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public KeyInfoType KeyInfo
        {
            get
            {
                return this.keyInfoField;
            }
            set
            {
                this.keyInfoField = value;
                this.RaisePropertyChanged("KeyInfo");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Object", Order = 3)]
        public ObjectType[] Object
        {
            get
            {
                return this.objectField;
            }
            set
            {
                this.objectField = value;
                this.RaisePropertyChanged("Object");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string Id
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("Id");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class InternationalStringType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string langField;

        private string valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(Form = System.Xml.Schema.XmlSchemaForm.Qualified, Namespace = "http://www.w3.org/XML/1998/namespace")]
        public string lang
        {
            get
            {
                return this.langField;
            }
            set
            {
                this.langField = value;
                this.RaisePropertyChanged("lang");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute()]
        public string Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
                this.RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class ResponseBaseType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private Result resultField;

        private AnyType optionalOutputsField;

        private string requestIDField;

        private string profileField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public Result Result
        {
            get
            {
                return this.resultField;
            }
            set
            {
                this.resultField = value;
                this.RaisePropertyChanged("Result");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public AnyType OptionalOutputs
        {
            get
            {
                return this.optionalOutputsField;
            }
            set
            {
                this.optionalOutputsField = value;
                this.RaisePropertyChanged("OptionalOutputs");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string RequestID
        {
            get
            {
                return this.requestIDField;
            }
            set
            {
                this.requestIDField = value;
                this.RaisePropertyChanged("RequestID");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Profile
        {
            get
            {
                return this.profileField;
            }
            set
            {
                this.profileField = value;
                this.RaisePropertyChanged("Profile");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Result : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string resultMajorField;

        private string resultMinorField;

        private InternationalStringType resultMessageField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "anyURI", Order = 0)]
        public string ResultMajor
        {
            get
            {
                return this.resultMajorField;
            }
            set
            {
                this.resultMajorField = value;
                this.RaisePropertyChanged("ResultMajor");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "anyURI", Order = 1)]
        public string ResultMinor
        {
            get
            {
                return this.resultMinorField;
            }
            set
            {
                this.resultMinorField = value;
                this.RaisePropertyChanged("ResultMinor");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 2)]
        public InternationalStringType ResultMessage
        {
            get
            {
                return this.resultMessageField;
            }
            set
            {
                this.resultMessageField = value;
                this.RaisePropertyChanged("ResultMessage");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class AttachmentReferenceType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private DigestMethodType digestMethodField;

        private byte[] digestValueField;

        private string attRefURIField;

        private string mimeTypeField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        public DigestMethodType DigestMethod
        {
            get
            {
                return this.digestMethodField;
            }
            set
            {
                this.digestMethodField = value;
                this.RaisePropertyChanged("DigestMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", DataType = "base64Binary", Order = 1)]
        public byte[] DigestValue
        {
            get
            {
                return this.digestValueField;
            }
            set
            {
                this.digestValueField = value;
                this.RaisePropertyChanged("DigestValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string AttRefURI
        {
            get
            {
                return this.attRefURIField;
            }
            set
            {
                this.attRefURIField = value;
                this.RaisePropertyChanged("AttRefURI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string MimeType
        {
            get
            {
                return this.mimeTypeField;
            }
            set
            {
                this.mimeTypeField = value;
                this.RaisePropertyChanged("MimeType");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class InlineXMLType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private System.Xml.XmlElement anyField;

        private bool ignorePIsField;

        private bool ignoreCommentsField;

        public InlineXMLType()
        {
            this.ignorePIsField = true;
            this.ignoreCommentsField = true;
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAnyElementAttribute(Order = 0)]
        public System.Xml.XmlElement Any
        {
            get
            {
                return this.anyField;
            }
            set
            {
                this.anyField = value;
                this.RaisePropertyChanged("Any");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        [System.ComponentModel.DefaultValueAttribute(true)]
        public bool ignorePIs
        {
            get
            {
                return this.ignorePIsField;
            }
            set
            {
                this.ignorePIsField = value;
                this.RaisePropertyChanged("ignorePIs");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        [System.ComponentModel.DefaultValueAttribute(true)]
        public bool ignoreComments
        {
            get
            {
                return this.ignoreCommentsField;
            }
            set
            {
                this.ignoreCommentsField = value;
                this.RaisePropertyChanged("ignoreComments");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Xml.Serialization.XmlIncludeAttribute(typeof(DocumentType))]
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public abstract partial class DocumentBaseType : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string idField;

        private string refURIField;

        private string refTypeField;

        private string schemaRefsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "ID")]
        public string ID
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
                this.RaisePropertyChanged("ID");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string RefURI
        {
            get
            {
                return this.refURIField;
            }
            set
            {
                this.refURIField = value;
                this.RaisePropertyChanged("RefURI");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string RefType
        {
            get
            {
                return this.refTypeField;
            }
            set
            {
                this.refTypeField = value;
                this.RaisePropertyChanged("RefType");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "IDREFS")]
        public string SchemaRefs
        {
            get
            {
                return this.schemaRefsField;
            }
            set
            {
                this.schemaRefsField = value;
                this.RaisePropertyChanged("SchemaRefs");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class DocumentType : DocumentBaseType
    {

        private object itemField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("AttachmentReference", typeof(AttachmentReferenceType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Base64Data", typeof(Base64Data), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Base64XML", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("EscapedXML", typeof(string), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("InlineXML", typeof(InlineXMLType), Order = 0)]
        public object Item
        {
            get
            {
                return this.itemField;
            }
            set
            {
                this.itemField = value;
                this.RaisePropertyChanged("Item");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Base64Data : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string mimeTypeField;

        private byte[] valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string MimeType
        {
            get
            {
                return this.mimeTypeField;
            }
            set
            {
                this.mimeTypeField = value;
                this.RaisePropertyChanged("MimeType");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute(DataType = "base64Binary")]
        public byte[] Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
                this.RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class InputDocuments : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object[] itemsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Document", typeof(DocumentType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("DocumentHash", typeof(DocumentHash), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Other", typeof(AnyType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("TransformedData", typeof(TransformedData), Order = 0)]
        public object[] Items
        {
            get
            {
                return this.itemsField;
            }
            set
            {
                this.itemsField = value;
                this.RaisePropertyChanged("Items");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class DocumentHash : DocumentBaseType
    {

        private TransformType[] transformsField;

        private DigestMethodType digestMethodField;

        private byte[] digestValueField;

        private string whichReferenceField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArrayAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlArrayItemAttribute("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return this.transformsField;
            }
            set
            {
                this.transformsField = value;
                this.RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 1)]
        public DigestMethodType DigestMethod
        {
            get
            {
                return this.digestMethodField;
            }
            set
            {
                this.digestMethodField = value;
                this.RaisePropertyChanged("DigestMethod");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", DataType = "base64Binary", Order = 2)]
        public byte[] DigestValue
        {
            get
            {
                return this.digestValueField;
            }
            set
            {
                this.digestValueField = value;
                this.RaisePropertyChanged("DigestValue");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "integer")]
        public string WhichReference
        {
            get
            {
                return this.whichReferenceField;
            }
            set
            {
                this.whichReferenceField = value;
                this.RaisePropertyChanged("WhichReference");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class TransformedData : DocumentBaseType
    {

        private TransformType[] transformsField;

        private Base64Data base64DataField;

        private string whichReferenceField;

        /// <remarks/>
        [System.Xml.Serialization.XmlArrayAttribute(Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlArrayItemAttribute("Transform", IsNullable = false)]
        public TransformType[] Transforms
        {
            get
            {
                return this.transformsField;
            }
            set
            {
                this.transformsField = value;
                this.RaisePropertyChanged("Transforms");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 1)]
        public Base64Data Base64Data
        {
            get
            {
                return this.base64DataField;
            }
            set
            {
                this.base64DataField = value;
                this.RaisePropertyChanged("Base64Data");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "integer")]
        public string WhichReference
        {
            get
            {
                return this.whichReferenceField;
            }
            set
            {
                this.whichReferenceField = value;
                this.RaisePropertyChanged("WhichReference");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignResponse : ResponseBaseType
    {

        private SignatureObject signatureObjectField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Order = 0)]
        public SignatureObject SignatureObject
        {
            get
            {
                return this.signatureObjectField;
            }
            set
            {
                this.signatureObjectField = value;
                this.RaisePropertyChanged("SignatureObject");
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignatureObject : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object itemField;

        private string schemaRefsField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Signature", typeof(SignatureType), Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Base64Signature", typeof(Base64Signature), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Other", typeof(AnyType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("SignaturePtr", typeof(SignaturePtr), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Timestamp", typeof(Timestamp), Order = 0)]
        public object Item
        {
            get
            {
                return this.itemField;
            }
            set
            {
                this.itemField = value;
                this.RaisePropertyChanged("Item");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "IDREFS")]
        public string SchemaRefs
        {
            get
            {
                return this.schemaRefsField;
            }
            set
            {
                this.schemaRefsField = value;
                this.RaisePropertyChanged("SchemaRefs");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>ute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Base64Signature : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string typeField;

        private byte[] valueField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "anyURI")]
        public string Type
        {
            get
            {
                return this.typeField;
            }
            set
            {
                this.typeField = value;
                this.RaisePropertyChanged("Type");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlTextAttribute(DataType = "base64Binary")]
        public byte[] Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
                this.RaisePropertyChanged("Value");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class SignaturePtr : object, System.ComponentModel.INotifyPropertyChanged
    {

        private string whichDocumentField;

        private string xPathField;

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute(DataType = "IDREF")]
        public string WhichDocument
        {
            get
            {
                return this.whichDocumentField;
            }
            set
            {
                this.whichDocumentField = value;
                this.RaisePropertyChanged("WhichDocument");
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlAttributeAttribute()]
        public string XPath
        {
            get
            {
                return this.xPathField;
            }
            set
            {
                this.xPathField = value;
                this.RaisePropertyChanged("XPath");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:oasis:names:tc:dss:1.0:core:schema")]
    public partial class Timestamp : object, System.ComponentModel.INotifyPropertyChanged
    {

        private object itemField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Signature", typeof(SignatureType), Namespace = "http://www.w3.org/2000/09/xmldsig#", Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("Other", typeof(AnyType), Order = 0)]
        [System.Xml.Serialization.XmlElementAttribute("RFC3161TimeStampToken", typeof(byte[]), DataType = "base64Binary", Order = 0)]
        public object Item
        {
            get
            {
                return this.itemField;
            }
            set
            {
                this.itemField = value;
                this.RaisePropertyChanged("Item");
            }
        }

        public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

        protected void RaisePropertyChanged(string propertyName)
        {
            System.ComponentModel.PropertyChangedEventHandler propertyChanged = this.PropertyChanged;
            if ((propertyChanged != null))
            {
                propertyChanged(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }
        }
    }

    /// <summary>
    /// Internal class, do not use directly.
    /// </summary>
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
    public partial class StampRequest
    {

        [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema", Order = 0)]
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
    [System.Diagnostics.DebuggerStepThroughAttribute()]
    [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
    [System.ServiceModel.MessageContractAttribute(IsWrapped = false)]
    public partial class StampResponse
    {

        [System.ServiceModel.MessageBodyMemberAttribute(Namespace = "urn:oasis:names:tc:dss:1.0:core:schema", Order = 0)]
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
    [System.Diagnostics.DebuggerStepThroughAttribute()]
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
        /// <param name="endpointConfigurationName">The configuration name of the application config</param>
        public TimeStampAuthorityClient(string endpointConfigurationName) :
            base(endpointConfigurationName)
        {
        }

        /// <summary>
        /// Uses the configuration wit the provided name from the application config, but overrides the address.
        /// </summary>
        /// <param name="endpointConfigurationName">The configuration name of the application conifg</param>
        /// <param name="remoteAddress">The address of the TSA (without ?wsdl at the end)</param>
        public TimeStampAuthorityClient(string endpointConfigurationName, string remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
        {
        }

        /// <summary>
        /// Uses the configuration wit the provided name from the application config, but overrides the address.
        /// </summary>
        /// <param name="endpointConfigurationName">The configuration name of the application config</param>
        /// <param name="remoteAddress">The address of the TSA</param>
        public TimeStampAuthorityClient(string endpointConfigurationName, System.ServiceModel.EndpointAddress remoteAddress) :
            base(endpointConfigurationName, remoteAddress)
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

        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Advanced)]
        Egelke.EHealth.Client.Pki.DSS.StampResponse Egelke.EHealth.Client.Pki.DSS.TimeStampAuthority.Stamp(Egelke.EHealth.Client.Pki.DSS.StampRequest request)
        {
            return base.Channel.Stamp(request);
        }

        /// <summary>
        /// Method used by the library, do not call.
        /// </summary>
        public SignResponse Stamp(SignRequest SignRequest)
        {
            StampRequest inValue = new StampRequest();
            inValue.SignRequest = SignRequest;
            StampResponse retVal = ((TimeStampAuthority)(this)).Stamp(inValue);
            return retVal.SignResponse;
        }
    }
#pragma warning restore 1591
}