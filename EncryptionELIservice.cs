using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionDecryptionClassLibrary
{
    public static class EncryptionDecryptionService
    {
        static readonly string PASSWORD_HASH = "fsdf#4345VDXVVXc";
        static readonly string SALT_KEY = "KLltyL1k34S41lr0";
        static readonly string VI_KEY = "zUe@cz8cz%j9HWE3y!";
        const int BUFFER_SIZE = 1 << 16;                            // should always be power of 2

        public static string DecryptText(string encryptedText)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PASSWORD_HASH, Encoding.ASCII.GetBytes(SALT_KEY)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VI_KEY));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

            memoryStream.Close();
            cryptoStream.Close();

            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }

        public static string EncryptText(string plainText)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PASSWORD_HASH, Encoding.ASCII.GetBytes(SALT_KEY)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VI_KEY));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return Convert.ToBase64String(cipherTextBytes);
        }

        public static string publicKey(Stream inputStream)
        {
            string output;

            using (StreamReader reader = new StreamReader(inputStream, Encoding.Default, true))
            {
                output = reader.ReadToEnd();
            }

            return output;
        }

        public static void GetString(Stream inputStream, string decriptedFile)
        {
            using (StreamReader reader = new StreamReader(inputStream, Encoding.Default, true))
            {
                String strDataLine = "";

                using (StreamWriter streamWriter = new StreamWriter(decriptedFile, true, Encoding.UTF8))
                {
                    strDataLine = reader.ReadLine();
                    if (strDataLine != null)
                    {
                        while ((strDataLine = reader.ReadLine()) != null)
                        {
                            streamWriter.WriteLine(strDataLine);
                        }
                    }
                }
            }
        }

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        #region Decrypt methods
        /// <summary>
        /// Decrypt Pgp Data
        /// </summary>
        /// <param name="inputStream">Public Input Stream</param>
        /// <param name="privateKeyStream">Private Key Stream</param>
        /// <param name="passPhrase">Pass Phrase</param>
        /// <returns>Decrypt</returns>
        public static void DecryptPgpData(string decriptedFile, Stream inputStream, Stream privateKeyStream, string passPhrase)
        {
            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            if (encryptedData == null)
                throw new PgpException("Encrypted data is NULL.");

            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pubKeyData = null;
            foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pubKeyData = pubKeyDataItem;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact = null;
            using (Stream clear = pubKeyData.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData compressedData = (PgpCompressedData)message;
                PgpObjectFactory pgpCompressedFactory = null;

                using (Stream compDataIn = compressedData.GetDataStream())
                {
                    pgpCompressedFactory = new PgpObjectFactory(compDataIn);
                }

                message = pgpCompressedFactory.NextPgpObject();
                PgpLiteralData literalData = null;
                if (message is PgpOnePassSignatureList)
                    message = pgpCompressedFactory.NextPgpObject();

                literalData = (PgpLiteralData)message;

                using (Stream unc = literalData.GetInputStream())
                {
                    GetString(unc, decriptedFile);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData literalData = (PgpLiteralData)message;
                using (Stream unc = literalData.GetInputStream())
                {
                    GetString(unc, decriptedFile);
                }
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }
        }

        /// <summary>
        /// Decrypt File
        /// </summary>
        /// <param name="encryptedStream">Encrypted Stream</param>
        /// <param name="privateKey">Private Key</param>
        /// <param name="passPhrase">Pass Phrase</param>
        /// <returns>Decrypt</returns>
        public static void DecryptDataFile(string decriptedFile, FileStream encryptedStream, string privateKey, string passPhrase)
        {
            Stream pgpFile = null;
            using (pgpFile = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(privateKey)))

            DecryptPgpData(decriptedFile, encryptedStream, pgpFile, passPhrase);
        }
        #endregion

        /// <summary>
        /// Read public key
        /// </summary>
        /// <param name="fileName">Public key file name</param>
        /// <returns>PGP public key</returns>
        public static PgpPublicKey ReadPublicKey(string fileName, bool readFromFile = false)
        {
            if (readFromFile)
            {
                using (Stream keyIn = File.OpenRead(fileName))
                {
                    return ReadPublicKey(publicKey(keyIn));
                }
            }
            else
            {
                byte[] byteArray = Encoding.UTF8.GetBytes(fileName);
                MemoryStream streamTemp = new MemoryStream(byteArray);
                return ReadPublicKey(streamTemp);
            }
        }

        /// <summary>
        /// A simple routine that opens a key ring file and loads the first available key suitable for encryption
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <returns>PGP public key</returns>
        private static PgpPublicKey ReadPublicKey(Stream input)
        {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            // We just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.			
            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                        return key;
                }
            }
            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        #region Encrypt methods
        /// <summary>
        /// Encrypt input file
        /// </summary>        
        /// <param name="inputFileName">Input file name</param>
        /// <param name="outputFileName">Output file name</param>
        /// <param name="publicKeyFileName">Public key PgpPublicKey</param>
        /// <param name="armor">Armored output</param>
        /// <param name="withIntegrityCheck">Integrity check flag</param>
        public static void EncryptFile(string inputFileName, string outputFileName, PgpPublicKey encKey, bool armor, bool withIntegrityCheck)
        {
            using (Stream output = File.Create(outputFileName))
            {
                EncryptFile(output, inputFileName, encKey, armor, withIntegrityCheck);
            }
        }

        /// <summary>
        /// Encrypt input file
        /// </summary>        
        /// <param name="inputFileName">Input file name</param>
        /// <param name="outputFileName">Output file name</param>
        /// <param name="publicKeyFileName">Public key file name</param>
        /// <param name="armor">Armored output</param>
        /// <param name="withIntegrityCheck">Integrity check flag</param>
        public static void EncryptFile(string inputFileName, string outputFileName, string publicKeyFileName, bool armor, bool withIntegrityCheck)
        {
            PgpPublicKey encKey = ReadPublicKey(publicKeyFileName);
            using (Stream output = File.Create(outputFileName))
            {
                EncryptFile(output, inputFileName, encKey, armor, withIntegrityCheck);
            }
        }

        /// <summary>
        /// Encrypt input file
        /// </summary>
        /// <param name="outputStream">Output file stream</param>
        /// <param name="inputFileName">Input file name</param>
        /// <param name="publicKey">PGP public key</param>
        /// <param name="armor">Armored output flag</param>
        /// <param name="withIntegrityCheck">Integrity check flag</param>
        private static void EncryptFile(Stream outputStream, string inputFileName, PgpPublicKey publicKey, bool armor, bool withIntegrityCheck)
        {
            if (armor)
                outputStream = new ArmoredOutputStream(outputStream);

            // byte[] bytes = CompressFile(inputFileName, CompressionAlgorithmTag.Zip);
            FileInfo compresedFile = CompressFile(inputFileName);

            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
            encGen.AddMethod(publicKey);

            //Stream cOut = encGen.Open(outputStream, bytes.Length);
            //cOut.Write(bytes, 0, bytes.Length);
            //cOut.Close();

            using (FileStream inputStream = compresedFile.OpenRead())
            {
                byte[] buf = new byte[BUFFER_SIZE];
                int len;
                while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
                {
                    outputStream.Write(buf, 0, len);
                }
            }

            if (compresedFile.Exists)
                compresedFile.Delete();

            if (armor)
                outputStream.Close();
        }
        #endregion

        /// <summary>
        /// Compress file
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="compressedFileName">Algorithm tag</param>
        /// <returns>Byte array</returns>
        private static FileInfo CompressFile(string inputFileName)
        {
            string outPutFileName = inputFileName + DateTime.Now.ToString("yyyyMMddHHMMss");
            FileInfo outputFileInfo = new FileInfo(outPutFileName);

            // Create new file.
            using (FileStream outputStream = outputFileInfo.Create())
            {
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                PgpUtilities.WriteFileToLiteralData(comData.Open(outputStream), PgpLiteralData.Binary, new FileInfo(inputFileName));
                comData.Close();
            }

            return outputFileInfo;
        }

        /// <summary>
        /// Compress file
        /// </summary>
        /// <param name="fileName">File name</param>
        /// <param name="algorithm">Algorithm tag</param>
        /// <returns>Byte array</returns>
        private static byte[] CompressFile(string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();
            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);

            // PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Utf8, new FileInfo(fileName));
            PgpUtilities.WriteFileToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, new FileInfo(fileName));
            comData.Close();

            return bOut.ToArray();
        }
    }
}
