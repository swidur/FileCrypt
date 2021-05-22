namespace Program
{
    using CommandLine;
    using Microsoft.AspNetCore.Cryptography.KeyDerivation;
    using Serilog;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// DISCLAIMER: This is not secure, nor tested application and should not be used with real data!
    /// Defines the <see cref="Program" />.
    /// </summary>
    public static class Program
    {
        internal const string MY_PREFIX = "encrypted_";

        internal const int DEF_ITERATIONS = 100000;

        internal const int AES_BITS = 256;

        internal const int AES_BLOCK = 128;

        internal const int KEY_SIZE = 32;

        internal const int IV_SIZE = 16;

        internal static void Main(string[] args)
        {

            bool encrypting = true;
            bool optionsSet = false;
            string inputFile = String.Empty;
            int iterations = DEF_ITERATIONS;
            string pass = String.Empty;
            byte[] key;
            byte[] iv;


            Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console()
            .CreateLogger();


            Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.Verbose)
                       {
                           Log.Logger = new LoggerConfiguration()
                            .MinimumLevel.Debug()
                            .WriteTo.Console()
                            .CreateLogger();
                           Log.Information("Verbosity set to high");
                       }
                       else
                       {
                           Log.Logger = new LoggerConfiguration()
                           .MinimumLevel.Information()
                           .WriteTo.Console()
                           .CreateLogger();
                       }

                       if (!String.IsNullOrEmpty(o.EncryptFile) && !String.IsNullOrEmpty(o.DecryptFile))
                       {
                           Log.Error("Either Encrypt or Decrypt, not both");
                       }
                       if (String.IsNullOrEmpty(o.EncryptFile) && String.IsNullOrEmpty(o.DecryptFile))
                       {
                           Log.Error("Either Encrypt or Decrypt, not neither");
                       }
                       if (!String.IsNullOrEmpty(o.EncryptFile))
                       {
                           Log.Debug($"File: --{o.EncryptFile}--");
                           inputFile = o.EncryptFile;
                           encrypting = true;
                           optionsSet = true;
                       }
                       else if (!String.IsNullOrEmpty(o.DecryptFile))
                       {
                           Log.Debug($"File: --{o.EncryptFile}--");
                           inputFile = o.DecryptFile;
                           encrypting = false;
                           optionsSet = true;
                       }
                       if (o.Iterations < 100000)
                       {
                           iterations = DEF_ITERATIONS;
                           Log.Debug($"Iterations: --{iterations}--");
                       }
                       Log.Debug($"Passphrase length: --{o.Passphrase.Length}--");
                       pass = o.Passphrase;
                   });

            if (optionsSet)
            {
                key = DeriveBytesFromText(pass, iterations, KEY_SIZE);
                iv = DeriveBytesFromText(pass, iterations, IV_SIZE);
                try
                {
                    if (encrypting)
                    {
                        Log.Debug($"Started encrypting file");
                        EncryptFile(inputFile, key, iv);
                    }
                    else
                    {
                        Log.Debug($"Started decrypting file");
                        DecryptFile(inputFile, key, iv);
                    }
                }
                catch (FileNotFoundException)
                {
                    Log.Error("Input file was not found");
                }
            }
        }

        private static byte[] DeriveBytesFromText(string passwordText, int iterations, int targetLen)
        {
            string mySalt = "34t-09bdflk4d94hj";

            var st = Stopwatch.StartNew();
            byte[] key = KeyDerivation.Pbkdf2(passwordText, Encoding.UTF8.GetBytes(mySalt), KeyDerivationPrf.HMACSHA512, iterations, targetLen);
            st.Stop();
            Log.Debug($"Pbkdf2 took: {st.ElapsedMilliseconds} ms for {targetLen} byte key");

            return key;
        }

        private static void EncryptFile(string inputFile, byte[] keyBytes, byte[] ivBytes)
        {
            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException($"inputFile: {inputFile}");
            }

            var inptFileName = Path.GetFileName(inputFile);
            var inptPath = Path.GetDirectoryName(inputFile) + Path.DirectorySeparatorChar;
            if (!Path.IsPathFullyQualified(inputFile))
            {
                inptPath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar;
            }
            string outputFile = inptPath + MY_PREFIX + inptFileName;

            var st = Stopwatch.StartNew();
            using (FileStream inputFileStream = File.Open(inputFile, FileMode.Open))
            using (FileStream outputFileStream = File.Open(outputFile, FileMode.Create))
            {
                Log.Debug($"File length: --{inputFileStream.Length}--");
                using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
                {
                    aesCryptoServiceProvider.KeySize = AES_BITS;
                    aesCryptoServiceProvider.BlockSize = AES_BLOCK;
                    aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;

                    aesCryptoServiceProvider.Key = keyBytes;
                    aesCryptoServiceProvider.IV = ivBytes;

                    ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateEncryptor();

                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[inputFileStream.Length];
                        inputFileStream.Read(buffer, 0, buffer.Length);
                        cryptoStream.Write(buffer, 0, buffer.Length);
                    }
                }
            }
            st.Stop();
            Log.Debug($"Encryption of file took: {st.ElapsedMilliseconds} ms == { st.ElapsedMilliseconds / 1000} s");
        }

        private static void DecryptFile(string inputFile, byte[] keyBytes, byte[] ivBytes)
        {

            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException($"inputFile: {inputFile}");
            }
            var inptFileName = Path.GetFileName(inputFile);
            var inptPath = Path.GetDirectoryName(inputFile) + Path.DirectorySeparatorChar;
            if (!Path.IsPathFullyQualified(inputFile))
            {
                inptPath = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar;
            }
            string outFileName;
            string outputFile;
            if (inptFileName.Contains(MY_PREFIX))
            {
                var arr = inptFileName.Split(MY_PREFIX);
                outFileName = "decrypted_" + arr[^1];
            }
            else
            {
                outFileName = "decrypted_" + inptFileName;
            }
            outputFile = inptPath + outFileName;

            var st = Stopwatch.StartNew();
            using (FileStream inputFileStream = File.Open(inputFile, FileMode.Open))
            using (FileStream outputFileStream = File.Open(outputFile, FileMode.Create))
            {
                Log.Debug($"File length: --{inputFileStream.Length}--");
                using (AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider())
                {
                    aesCryptoServiceProvider.KeySize = AES_BITS;
                    aesCryptoServiceProvider.BlockSize = AES_BLOCK;
                    aesCryptoServiceProvider.Padding = PaddingMode.PKCS7;
                    aesCryptoServiceProvider.Key = keyBytes;
                    aesCryptoServiceProvider.IV = ivBytes;

                    ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateDecryptor();

                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        byte[] buffer = new byte[inputFileStream.Length];
                        inputFileStream.Read(buffer, 0, buffer.Length);
                        cryptoStream.Write(buffer, 0, buffer.Length);
                    }

                }
            }
            st.Stop();
            Log.Debug($"Decryption of file took: {st.ElapsedMilliseconds} ms == { st.ElapsedMilliseconds / 1000} s");
        }
    }
}
