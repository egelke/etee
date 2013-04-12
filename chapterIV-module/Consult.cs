using System.Xml.Serialization;

//Used to be generated, but manually addepted to simplify usage.

namespace Egelke.EHealth.Client.ChapterIV.Consult {
    
    
    
    [System.Xml.Serialization.XmlTypeAttribute(Namespace="urn:be:cin:io:unsealed:medicalAdvisorAgreement:consult:v1")]
    [System.Xml.Serialization.XmlRootAttribute("Request", Namespace="urn:be:cin:io:unsealed:medicalAdvisorAgreement:consult:v1", IsNullable=false)]
    public partial class UnaddressedRequestType {
        
        private byte[] etkHcpField;
        
        private byte[] kmehrRequestField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] EtkHcp {
            get {
                return this.etkHcpField;
            }
            set {
                this.etkHcpField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] KmehrRequest {
            get {
                return this.kmehrRequestField;
            }
            set {
                this.kmehrRequestField = value;
            }
        }
    }
    
    [System.Xml.Serialization.XmlTypeAttribute(TypeName="RequestType", Namespace="urn:be:cin:io:sealed:medicalAdvisorAgreement:consult:v1")]
    [System.Xml.Serialization.XmlRootAttribute("Request", Namespace="urn:be:cin:io:sealed:medicalAdvisorAgreement:consult:v1", IsNullable=false)]
    public partial class AdressedRequestType {

        private CareReceiverIdType careReceiverField;
        
        private System.DateTime agreementStartDateField;
        
        private string unsealKeyIdField;
        
        private byte[] sealedContentField;
        
        /// <remarks/>
        public CareReceiverIdType CareReceiver {
            get {
                return this.careReceiverField;
            }
            set {
                this.careReceiverField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="date")]
        public System.DateTime AgreementStartDate {
            get {
                return this.agreementStartDateField;
            }
            set {
                this.agreementStartDateField = value;
            }
        }
        
        /// <remarks/>
        public string UnsealKeyId {
            get {
                return this.unsealKeyIdField;
            }
            set {
                this.unsealKeyIdField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] SealedContent {
            get {
                return this.sealedContentField;
            }
            set {
                this.sealedContentField = value;
            }
        }
    }
    

    [System.Xml.Serialization.XmlTypeAttribute(Namespace="urn:be:cin:io:unsealed:medicalAdvisorAgreement:consult:v1")]
    [System.Xml.Serialization.XmlRootAttribute("Response", Namespace="urn:be:cin:io:unsealed:medicalAdvisorAgreement:consult:v1", IsNullable=false)]
    public partial class ResponseType {
        
        private byte[] timestampReplyField;
        
        private byte[] kmehrResponseField;
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] TimestampReply {
            get {
                return this.timestampReplyField;
            }
            set {
                this.timestampReplyField = value;
            }
        }
        
        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType="base64Binary")]
        public byte[] KmehrResponse {
            get {
                return this.kmehrResponseField;
            }
            set {
                this.kmehrResponseField = value;
            }
        }
    }
}
