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

namespace Siemens.EHealth.Etee.Demo.Console
{
    class Program
    {
        private static LocalFilePostMaster pm;

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

                    BasicHttpBinding etkDepotBinding = new BasicHttpBinding(BasicHttpSecurityMode.Transport);
                    etkDepotBinding.Security.Transport.ClientCredentialType = HttpClientCredentialType.None;
                    EtkDepotPortTypeClient ektDepotClient = new EtkDepotPortTypeClient(etkDepotBinding, new EndpointAddress(etkDepot));

                    return new LocalFilePostMaster(SecurityInfo.Create(signingCerts[certId - 1]), ektDepotClient);
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
            string type;
            string app;
            string value;
            List<Recipient> recipients = new List<Recipient>();
            System.Console.WriteLine("The in.msg will be encrypted, please specify the recipients: ");
            while (true)
            {
                System.Console.Write("The value (leave empty to start encryption): ");
                value = System.Console.ReadLine();
                if (String.IsNullOrWhiteSpace(value)) break;
                System.Console.Write("The type [NIHII]: ");
                type = System.Console.ReadLine();
                if (String.IsNullOrWhiteSpace(type)) type = "NIHII";
                System.Console.Write("The application []: ");
                app = System.Console.ReadLine();

                if (String.IsNullOrWhiteSpace(app))
                {
                    recipients.Add(new KnownRecipient(type, value, app));
                }
                else
                {
                    recipients.Add(new KnownRecipient(type, value));
                }
            }

            try
            {
                System.Console.Write(String.Format("Input filename: "));
                String clearName = System.Console.ReadLine();
                System.Console.WriteLine("Opening the input file");
                FileStream clear = new FileStream(clearName, FileMode.Open);
                using (clear)
                {
                    System.Console.Write("Output filename: ");
                    pm.KeyName = null;
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
                    System.Console.Write("Input filename: ");
                    pm.KeyName = null;
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
                System.Console.WriteLine("Could not encrypt because: " + e.Message);
            }
        }
    }
}
