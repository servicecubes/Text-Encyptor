using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenSSLEncryption
{
    public interface IOpenSslAes
    {
        string Encrypt(string plainText, string passphrase);

        string Decrypt(string encrypted, string passphrase);

        void EncryptFile(string inputFilename, string outputFilename, string passphrase);

        void DecryptFile(string inputFilename, string outputFilename, string passphrase);

        bool IsFileEncrypted(string inputFileName);
    }

    public class OpenSslAes : IOpenSslAes
    {
        private static readonly Regex NonAsciiCharsRegex = new Regex(@"[\u0000-\u007F]", RegexOptions.Compiled);

        private enum CryptographyMode
        {
            Encryption,
            Decryption
        }

        public string Encrypt(string plainText, string passphrase)
        {
            var salt = new byte[8];

            using (var rngServieProvider = new RNGCryptoServiceProvider())
            {
                rngServieProvider.GetNonZeroBytes(salt);

                byte[] key;
                byte[] iv;

                EvpBytesToKey(passphrase, salt, out key, out iv);

                var encryptedBytes = AesEncrypt(plainText, key, iv);
                var encryptedBytesWithSalt = CombineSaltAndEncryptedData(encryptedBytes, salt);

                return Convert.ToBase64String(encryptedBytesWithSalt);
            }
        }

        public string Decrypt(string encrypted, string passphrase)
        {
            var encryptedBytesWithSalt = Convert.FromBase64String(encrypted);

            var salt = ExtractSalt(encryptedBytesWithSalt);
            var encryptedBytes = ExtractEncryptedData(salt, encryptedBytesWithSalt);

            byte[] key, iv;
            EvpBytesToKey(passphrase, salt, out key, out iv);

            return AesDecrypt(encryptedBytes, key, iv);
        }

        public void EncryptFile(string inputFilename, string outputFilename, string passphrase)
        {
            var salt = new byte[8];

            using (var rngServieProvider = new RNGCryptoServiceProvider())
            {
                rngServieProvider.GetNonZeroBytes(salt);

                using (var input = new FileStream(inputFilename, FileMode.Open, FileAccess.Read))
                {
                    using (var output = new FileStream(outputFilename, FileMode.Create, FileAccess.Write))
                    {
                        AesEncryptDecrypt(input, output, passphrase, salt, CryptographyMode.Encryption);
                    }
                }
            }
        }

        public void DecryptFile(string inputFilename, string outputFilename, string passphrase)
        {
            using (var input = new FileStream(inputFilename, FileMode.Open, FileAccess.Read))
            {
                using (var output = new FileStream(outputFilename, FileMode.Create, FileAccess.Write))
                {
                    var salt = ExtractSalt(input);

                    AesEncryptDecrypt(input, output, passphrase, salt, CryptographyMode.Decryption);
                }
            }
        }

        public bool IsFileEncrypted(string inputFileName)
        {
            const int ThresholdNonAsciiPercentage = 5;

            if (IsSalted(inputFileName))
            {
                return true;
            }

            using (var reader = new StreamReader(inputFileName))
            {
                var firstLine = reader.ReadLine();

                if (string.IsNullOrWhiteSpace(firstLine))
                {
                    return false;
                }

                var nonAsciiChars = NonAsciiCharsRegex.Replace(firstLine, string.Empty);

                return (nonAsciiChars.Length * 100 / firstLine.Length) >= ThresholdNonAsciiPercentage;
            }
        }

        private static byte[] AesEncrypt(string plainText, byte[] key, byte[] iv)
        {
            MemoryStream memoryStream = null;
            RijndaelManaged aesAlgorithm = null;

            try
            {
                aesAlgorithm = new RijndaelManaged
                {
                    Mode = CipherMode.CBC,
                    KeySize = 256,
                    BlockSize = 128,
                    Key = key,
                    IV = iv
                };

                var cryptoTransform = aesAlgorithm.CreateEncryptor(aesAlgorithm.Key, aesAlgorithm.IV);
                memoryStream = new MemoryStream();

                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                        streamWriter.Flush();
                        streamWriter.Close();
                    }
                }
            }
            finally
            {
                if (memoryStream != null)
                {
                    memoryStream.Dispose();
                }

                if (aesAlgorithm != null)
                {
                    aesAlgorithm.Dispose();
                }
            }

            return memoryStream.ToArray();
        }

        private static string AesDecrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            RijndaelManaged aesAlgorithm = null;
            string plaintext;

            try
            {
                aesAlgorithm = new RijndaelManaged
                {
                    Mode = CipherMode.CBC,
                    KeySize = 256,
                    BlockSize = 128,
                    Key = key,
                    IV = iv
                };

                var decryptor = aesAlgorithm.CreateDecryptor(aesAlgorithm.Key, aesAlgorithm.IV);

                using (var memoryStream = new MemoryStream(cipherText))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            plaintext = streamReader.ReadToEnd();
                            streamReader.Close();
                        }
                    }
                }
            }
            finally
            {
                if (aesAlgorithm != null)
                {
                    aesAlgorithm.Dispose();
                }
            }

            return plaintext;
        }

        private static void AesEncryptDecrypt(
            Stream inputStream,
            Stream outStream,
            string passphrase,
            byte[] salt,
            CryptographyMode cryptographyMode)
        {
            RijndaelManaged aesAlgorithm = null;

            try
            {
                byte[] key, iv;
                EvpBytesToKey(passphrase, salt, out key, out iv);

                aesAlgorithm = new RijndaelManaged
                {
                    Mode = CipherMode.CBC,
                    KeySize = 256,
                    BlockSize = 128,
                    Key = key,
                    IV = iv
                };

                var cryptoTransform = cryptographyMode == CryptographyMode.Encryption ?
                                                       aesAlgorithm.CreateEncryptor(aesAlgorithm.Key, aesAlgorithm.IV) :
                                                       aesAlgorithm.CreateDecryptor(aesAlgorithm.Key, aesAlgorithm.IV);

                if (cryptographyMode == CryptographyMode.Encryption)
                {
                    var encryptedBytesWithSalt = new byte[salt.Length + 8];
                    Buffer.BlockCopy(Encoding.UTF8.GetBytes("Salted__"), 0, encryptedBytesWithSalt, 0, 8);
                    Buffer.BlockCopy(salt, 0, encryptedBytesWithSalt, 8, salt.Length);
                    outStream.Write(encryptedBytesWithSalt, 0, encryptedBytesWithSalt.Length);
                }

                using (var cryptoStream = new CryptoStream(outStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    var byteCount = inputStream.Length - inputStream.Position;

                    // Read 500 MB data at a time
                    const int ChunkSize = 500 * 1024 * 1024;

                    var chunkcount = (int)(byteCount / ChunkSize);
                    var bytesRemaining = (int)(byteCount % ChunkSize);

                    if (chunkcount > 0)
                    {
                        for (long i = 0; i < chunkcount; i++)
                        {
                            var chunkData = new byte[ChunkSize];
                            inputStream.Read(chunkData, 0, ChunkSize);
                            cryptoStream.Write(chunkData, 0, chunkData.Length);
                        }
                    }

                    if (bytesRemaining > 0)
                    {
                        var chunkData = new byte[bytesRemaining];
                        inputStream.Read(chunkData, 0, bytesRemaining);
                        cryptoStream.Write(chunkData, 0, chunkData.Length);
                    }
                }
            }
            finally
            {
                if (aesAlgorithm != null)
                {
                    aesAlgorithm.Dispose();
                }
            }
        }

        // OpenSSL prefixes the combined encrypted data and salt with "Salted__"
        private static byte[] CombineSaltAndEncryptedData(byte[] encryptedData, byte[] salt)
        {
            var encryptedBytesWithSalt = new byte[salt.Length + encryptedData.Length + 8];
            Buffer.BlockCopy(Encoding.UTF8.GetBytes("Salted__"), 0, encryptedBytesWithSalt, 0, 8);
            Buffer.BlockCopy(salt, 0, encryptedBytesWithSalt, 8, salt.Length);
            Buffer.BlockCopy(encryptedData, 0, encryptedBytesWithSalt, salt.Length + 8, encryptedData.Length);
            return encryptedBytesWithSalt;
        }

        // Pull the data out from the combined salt and data
        private static byte[] ExtractEncryptedData(ICollection<byte> salt, byte[] encryptedBytesWithSalt)
        {
            var encryptedBytes = new byte[encryptedBytesWithSalt.Length - salt.Count - 8];
            Buffer.BlockCopy(encryptedBytesWithSalt, salt.Count + 8, encryptedBytes, 0, encryptedBytes.Length);
            return encryptedBytes;
        }

        // The salt is located in the first 8 bytes of the combined encrypted data and salt bytes
        private static byte[] ExtractSalt(byte[] encryptedBytesWithSalt)
        {
            var salt = new byte[8];
            Buffer.BlockCopy(encryptedBytesWithSalt, 8, salt, 0, salt.Length);
            return salt;
        }

        // The salt is located in the first 8 bytes of the combined encrypted data and salt bytes
        private static byte[] ExtractSalt(Stream inputFile)
        {
            byte[] salt = null;

            if (inputFile.Length > 16)
            {
                var salted = new byte[8];

                if (inputFile.Read(salted, 0, 8) > 0 && Encoding.UTF8.GetString(salted) == "Salted__")
                {
                    salt = new byte[8];
                    inputFile.Read(salt, 0, salt.Length);
                }
                else
                {
                    salt = new byte[0];
                    inputFile.Position = 0;
                }
            }

            return salt;
        }

        // Key derivation algorithm used by OpenSSL
        // Derives a key and IV from the passphrase and salt using a hash algorithm (in this case, MD5).
        // Refer to http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
        private static void EvpBytesToKey(string passphrase, byte[] salt, out byte[] key, out byte[] iv)
        {
            var concatenatedHashes = new List<byte>(48);

            var password = Encoding.UTF8.GetBytes(passphrase);
            var currentHash = new byte[0];

            using (var md5 = MD5.Create())
            {
                var enoughBytesForKey = false;

                while (!enoughBytesForKey)
                {
                    var preHashLength = currentHash.Length + password.Length + salt.Length;
                    var preHash = new byte[preHashLength];

                    Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
                    Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
                    Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);

                    currentHash = md5.ComputeHash(preHash);
                    concatenatedHashes.AddRange(currentHash);

                    if (concatenatedHashes.Count >= 48)
                    {
                        enoughBytesForKey = true;
                    }
                }

                key = new byte[32];
                iv = new byte[16];
                concatenatedHashes.CopyTo(0, key, 0, 32);
                concatenatedHashes.CopyTo(32, iv, 0, 16);

                md5.Clear();
            }
        }

        private static bool IsSalted(string fileName)
        {
            using (var inputFileStream = File.OpenRead(fileName))
            {
                var salted = new byte[8];

                if (inputFileStream.Length <= 8)
                {
                    return true;
                }

                inputFileStream.Read(salted, 0, 8);

                if (Encoding.UTF8.GetString(salted) != "Salted__")
                {
                    return false;
                }
            }

            return true;
        }
    }
}