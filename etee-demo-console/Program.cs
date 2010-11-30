using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Siemens.EHealth.Etee.Crypto.Library;
using Siemens.EHealth.Etee.Crypto.Library.ServiceClient;
using System.ServiceModel;
using System.IO;
using System.Collections.ObjectModel;
using System.Deployment.Application;
using System.IO.IsolatedStorage;
using System.Text.RegularExpressions;
using Siemens.EHealth.Client.Sso;
using System.IdentityModel.Tokens;
using Siemens.EHealth.Client.Sso.Sts;
using System.Xml;
using System.ServiceModel.Security.Tokens;
using System.ServiceModel.Description;
using Siemens.EHealth.Client.Sso.WA;

namespace Siemens.EHealth.Etee.Demo.Console
{
    class Program
    {
        private static LocalFilePostMaster pm;
        private static readonly Regex certParse = new Regex(@"CN=""?(?<type>\w*)\\?=(?<value>\d*)");
        private static readonly Regex knownParse = new Regex(@"(?<type>\w*)=(?<value>\d*)(,\s)?(?<app>\w*)?");
        private static readonly Regex unknownParse = new Regex(@"\{(?<ns>.*)\}(?<name>[^=]*)=?(?<value>\d*)?");

        static void Main(string[] args)
        {
            System.Console.WriteLine("************************************************");
            System.Console.WriteLine("*                                              *");
            System.Console.WriteLine("* Welcome to the ETEE Demo Console application *");
            System.Console.WriteLine("*                                              *");
            System.Console.WriteLine("************************************************");
            System.Console.WriteLine();

            pm = Setup(args);

            bool next = true;
            while (next)
            {
                System.Console.WriteLine();
                System.Console.Write("Please provide command (h or help for help): ");
                String command = System.Console.ReadLine();
                switch (command.ToLower())
                {
                    case "h":
                    case "help":
                        Help();
                        break;
                    case "e":
                    case "s":
                    case "encrypt":
                    case "seal":
                        Encrypt();
                        break;
                    case "d":
                    case "u":
                    case "decrypt":
                    case "unseal":
                        Decrypt();
                        break;
                    case "q":
                    case "quit":
                        next = false;
                        break;
                    default:
                        System.Console.WriteLine("Unknown command, use h for list of commands");
                        break;
                }
            }
            System.Console.Write("Press enter to continue...");
            System.Console.ReadLine();
        }



        private static LocalFilePostMaster Setup(string[] args)
        {
            //Determine the urls
            String etkDepot = null;
            String sts = null;
            String kgss= null;
            foreach(string arg in args)
            {
                if (arg.ToLower().Contains("etkdepot"))
                {
                    etkDepot = arg;
                    System.Console.WriteLine("Found Etk Depot url in params: " + etkDepot);
                }
                else if (arg.ToLower().Contains("securetokenservice"))
                {
                    sts = arg;
                    System.Console.WriteLine("Found Secure Token Service url in params: " + sts);
                }
                else if (arg.ToLower().Contains("kgss"))
                {
                    kgss = arg;
                    System.Console.WriteLine("Found KGSS url in params: " + kgss);
                } 
                else
                {
                    System.Console.WriteLine("Found unknown param: " + arg);
                }
            }
            if (etkDepot == null)
            {
                etkDepot = "https://services-acpt.ehealth.fgov.be/EtkDepot/v1";
                System.Console.WriteLine("Using default ETK Depot url: " + etkDepot);
            }
            if (sts == null)
            {
                sts = "https://wwwacc.ehealth.fgov.be/sts_1_1/SecureTokenService";
                System.Console.WriteLine("Using default Secure Token Service url: " + sts);
            }
            if (kgss == null)
            {
                kgss = "https://services-acpt.ehealth.fgov.be/Kgss/v1";
                System.Console.WriteLine("Using default KGSS url: " + kgss);
            }
            System.Console.WriteLine();

            //Get the certificate & return the PostMaster
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadOnly);
            try
            {
                System.Console.WriteLine("Lookiong for _valid_ eHealth certificates");
                X509Certificate2Collection ehCerts = my.Certificates.Find(X509FindType.FindBySubjectName, "eHealth-platform Belgium", true);
                X509Certificate2Collection signingCerts = ehCerts.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.DigitalSignature, true);
                if (signingCerts.Count == 0)
                {
                    System.Console.WriteLine("Could not find any signing certs, exiting");
                    Environment.Exit(1);
                }

                while (true)
                {
                    System.Console.WriteLine("eHealth authentication certificates:");
                    for (int i = 0; i < signingCerts.Count; i++)
                    {
                        System.Console.WriteLine(String.Format("\t{0}: {1}\n\t\tSubject: {2}\n\t\tIssuer: {3}", i + 1, signingCerts[i].FriendlyName,
                            signingCerts[i].Subject, signingCerts[i].Issuer));
                    }
                    System.Console.Write("Select certificate: ");
                    string selection = System.Console.ReadLine();
                    int certId;
                    if (!int.TryParse(selection, out certId))
                    {
                        System.Console.WriteLine("You must type the ID (number) of the certificate");
                        continue;
                    }
                    if (certId < 1 || certId > signingCerts.Count)
                    {
                        System.Console.WriteLine("ID (number) of the certificate must be listed");
                        continue;
                    }
                    X509Certificate2 cert = signingCerts[certId - 1];

                    BasicHttpBinding etkDepotBinding = new BasicHttpBinding(BasicHttpSecurityMode.Transport);
                    etkDepotBinding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                    EtkDepotPortTypeClient ektDepotClient = new EtkDepotPortTypeClient(etkDepotBinding, new EndpointAddress(etkDepot));

                    SsoBinding kgssBinding = new SsoBinding();
                    kgssBinding.Security.Mode = WSFederationHttpSecurityMode.Message;
                    kgssBinding.Security.Message.IssuedKeyType = SecurityKeyType.AsymmetricKey;
                    kgssBinding.Security.Message.NegotiateServiceCredential = false;
                    kgssBinding.Security.Message.EstablishSecurityContext = false;
                    kgssBinding.Security.Message.IssuerAddress = new EndpointAddress(sts);
                    kgssBinding.Security.Message.IssuerBinding = new StsBinding();
                    kgssBinding.Security.Message.IssuedTokenType = SecurityTokenTypes.Saml;
                    Match certCN = certParse.Match(cert.Subject);
                    if (!certCN.Groups["type"].Success || !certCN.Groups["value"].Success)
                    {
                        System.Console.WriteLine("The selected certifcate doesn't have a valid CN");
                        continue;
                    }
                    string type = certCN.Groups["type"].Value;
                    string value = certCN.Groups["value"].Value;
                    switch (type)
                    {
                        case "CBE":
                            //TODO: make dynamic...
                            XmlDocument doc = new XmlDocument();
                            doc.LoadXml(String.Format("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:kbo-cbe:cbe-number\">" +
                                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">{0}</saml:AttributeValue>" +
                                "</saml:Attribute>", value));
                            kgssBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);
                            doc = new XmlDocument();
                            doc.LoadXml(String.Format("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AttributeNamespace=\"urn:be:fgov:identification-namespace\" AttributeName=\"urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number\">" +
                                "<saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">{0}</saml:AttributeValue>" +
                                "</saml:Attribute>", value));
                            kgssBinding.Security.Message.TokenRequestParameters.Add(doc.DocumentElement);
                            kgssBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:kbo-cbe:cbe-number"));
                            kgssBinding.Security.Message.ClaimTypeRequirements.Add(new ClaimTypeRequirement("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number"));
                            break;
                        default:
                            System.Console.WriteLine("Sorry, this type of client isn't (yet) supported");
                            continue;
                    }
                    
                    KgssPortTypeClient kgssClient = new KgssPortTypeClient(kgssBinding, new EndpointAddress(kgss));
                    kgssClient.Endpoint.Behaviors.Remove<ClientCredentials>();
                    kgssClient.Endpoint.Behaviors.Add(new SsoClientCredentials());
                    //TODO: allow different certs for auth and session
                    kgssClient.Endpoint.Behaviors.Add(new SessionBehavior(cert, new TimeSpan(1, 0, 0)));
                    kgssClient.ClientCredentials.ClientCertificate.Certificate = cert; 

                    return new LocalFilePostMaster(SecurityInfo.Create(cert), ektDepotClient, kgssClient);
                }
            }
            finally
            {
                my.Close();
            }
        }

        private static void Help()
        {
            System.Console.WriteLine("\th or help - Print this message");
            System.Console.WriteLine("\te or encrypt - Encrypt for known recipient");
            System.Console.WriteLine("\ts or seal - Same as encrypt");
            System.Console.WriteLine("\td or decrypt - Decrypt for known recipient");
            System.Console.WriteLine("\tu or unseal - Same as decrypt");
            System.Console.WriteLine("\tq or quit - Quit this application");
        }

        private static void Encrypt()
        {

            int nr = 1;
            bool hasUnknown = false;
            List<Recipient> recipients = new List<Recipient>();
            System.Console.WriteLine(String.Format("Running pre-requisites of encryption"));
            System.Console.WriteLine("Specify the known recipients (leave emtpty to stop): ");
            System.Console.WriteLine("Format '<<Type>>=<<Value>>[, <<Application>>]'");
            System.Console.WriteLine("Example 'NIHII=00000000' or 'CBE=00000000000, MyApp'");
            while (true)
            {
                string type;
                string app;
                string value;
                string input;

                System.Console.Write(String.Format("{0} : ", nr));
                input = System.Console.ReadLine();
                if (String.IsNullOrWhiteSpace(input)) break;
                Match match = knownParse.Match(input);
                if (!match.Groups["type"].Success || !match.Groups["value"].Success)
                {
                    System.Console.WriteLine("The input was not in the correct format");
                    continue;
                }
                type = match.Groups["type"].Value;
                value = match.Groups["value"].Value;
                if (match.Groups["app"].Success && !String.IsNullOrWhiteSpace(match.Groups["app"].Value))
                {
                    app = match.Groups["app"].Value;
                    System.Console.WriteLine(String.Format("Adding '{0}={1}, {2}' to recipients", type, value, app));
                    recipients.Add(new KnownRecipient(type, value, app));
                }
                else
                {
                    app = null;
                    System.Console.WriteLine(String.Format("Adding '{0}={1}' to recipients", type, value));
                    recipients.Add(new KnownRecipient(type, value));
                }
                nr++;
            }
            System.Console.WriteLine("Specify the unknown recipients (leave emtpty to stop): ");
            System.Console.WriteLine("Format '{<<namespace>>}<<name>>[=<<value>>]', no value means everybody");
            System.Console.WriteLine("Example '{urn:be:fgov:identification-namespace}urn:be:fgov:kbo-cbe:cbe-number'");
            System.Console.WriteLine("Example '{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin=79021802145'");
            while (true)
            {
                string ns;
                string name;
                string value;
                string input;

                System.Console.Write(String.Format("{0} : ", nr));
                input = System.Console.ReadLine();
                if (String.IsNullOrWhiteSpace(input)) break;
                Match match = unknownParse.Match(input);
                if (!match.Groups["ns"].Success || !match.Groups["name"].Success)
                {
                    System.Console.WriteLine("The input was not in the correct format");
                    continue;
                }
                ns = match.Groups["ns"].Value;
                name = match.Groups["name"].Value;
                if (match.Groups["value"].Success && !String.IsNullOrWhiteSpace(match.Groups["value"].Value))
                {
                    value = match.Groups["value"].Value;
                    System.Console.WriteLine(String.Format("Adding '{{{0}}}{1}={2}' to recipients", ns, name, value));
                    recipients.Add(new UnknownRecipient(ns, name, value));
                }
                else
                {
                    value = null;
                    System.Console.WriteLine(String.Format("Adding '{{{0}}}{1}=*' to recipients", ns, name));
                    recipients.Add(new UnknownRecipient(ns, name, value));
                }
                nr++;
                hasUnknown = true;
            }

            try
            {
                System.Console.Write(String.Format("Input filename: "));
                String clearName = System.Console.ReadLine();
                System.Console.WriteLine("Opening the input file");
                FileStream clear = new FileStream(clearName, FileMode.Open);
                using (clear)
                {
                    if (hasUnknown)
                    {
                        System.Console.Write("Key filename: ");
                        pm.KeyName = System.Console.ReadLine();
                    }
                    else
                    {
                        pm.KeyName = null;
                    }
                    System.Console.Write("Output filename: ");
                    pm.MsgName = System.Console.ReadLine();
                    System.Console.WriteLine("Starting Encryption");
                    try
                    {
                        pm.Send(clear, new ReadOnlyCollection<Recipient>(recipients));
                    }
                    finally
                    {
                        System.Console.WriteLine("Finished Encryption");
                    }
                }
            }
            catch (Exception e)
            {
                System.Console.WriteLine("Could not encrypt because: " + e.Message);
                System.Console.WriteLine(e.StackTrace);
            }
        }

        private static void Decrypt()
        {
            try
            {
                System.Console.Write(String.Format("Output filename: "));
                String clearName = System.Console.ReadLine();
                System.Console.WriteLine("Opening the output file");
                FileStream clear = new FileStream(clearName, FileMode.Create);
                using (clear)
                {
                    System.Console.Write("Key filename (empty => no key => known recipient): ");
                    pm.KeyName = System.Console.ReadLine();
                    if (String.IsNullOrWhiteSpace(pm.KeyName)) pm.KeyName = null;
                    System.Console.Write("Input filename: ");
                    pm.MsgName = System.Console.ReadLine();
                    System.Console.WriteLine("Starting Decryption");
                    try
                    {
                        X509Certificate2 sender;
                        pm.Receive(clear, out sender);
                        System.Console.WriteLine(String.Format("Message from {0}", sender.Subject));
                    }
                    finally
                    {
                        System.Console.WriteLine("Finished Encryption");
                    }
                }
            }
            catch (Exception e)
            {
                System.Console.WriteLine("Could not decrypt because: " + e.Message);
                System.Console.WriteLine(e.StackTrace);
            }
        }
    }
}
