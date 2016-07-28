using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using OpenSSLEncryption;

namespace DatabaseCredentialsEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            OpenSslAes osa = new OpenSslAes();

            Console.WriteLine("Enter Database Server Name:");
            var dbServer = osa.Encrypt(Console.ReadLine(), ConfigurationManager.AppSettings["encryptKey"]);

            Console.WriteLine("Enter Database Name:");
            var dbDatabase = osa.Encrypt(Console.ReadLine(), ConfigurationManager.AppSettings["encryptKey"]);

            Console.WriteLine("Enter Database User Name:");
            var dbUser = osa.Encrypt(Console.ReadLine(), ConfigurationManager.AppSettings["encryptKey"]);

            Console.WriteLine("Enter Database Password:");
            var dbPassword = osa.Encrypt(Console.ReadLine(), ConfigurationManager.AppSettings["encryptKey"]);

            var filePath = @"..\EncryptedDBCredentials.txt";
            var fileText = "Your data is encrypted:\nDatabase Server:\t\t" + dbServer + "\nDatabase:\t\t\t\t" + dbDatabase + "\nDatabase User Name:\t\t" + dbUser + "\nDatabase Password:\t\t" + dbPassword;

            
            File.Create(filePath).Close();
            File.WriteAllText(filePath, fileText);
            Process.Start(filePath);
        }
    }
}
