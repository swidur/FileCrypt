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
            string inputOption = String.Empty;
            string outputOption = String.Empty;
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
                           inputOption = o.EncryptFile;
                           encrypting = true;
                           optionsSet = true;
                       }
                       else if (!String.IsNullOrEmpty(o.DecryptFile))
                       {
                           Log.Debug($"File: --{o.EncryptFile}--");
                           inputOption = o.DecryptFile;
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
                       outputOption = o.Output;
                   });

            if (optionsSet)
            {
                string input = String.Empty;
                string output = String.Empty;
                try
                {
                    (input, output) = FileNameHandler(encrypting, inputOption, outputOption);
                }
                catch (Exception)
                {

                }
                key = DeriveBytesFromText(pass, iterations, KEY_SIZE);
                iv = DeriveBytesFromText(pass, iterations, IV_SIZE);
                try
                {
                    if (encrypting)
                    {
                        Log.Debug($"Started encrypting file");
                        EncryptDecrypt(encrypting, input, output, key, iv);
                    }
                    else
                    {
                        Log.Debug($"Started decrypting file");
                        EncryptDecrypt(!encrypting, input, output, key, iv);
                    }
                }
                catch (FileNotFoundException)
                {
                    Log.Error("Input file was not found");
                }
            }
        }

        private static (string, string) FileNameHandler(bool encrypting, string inputFile, string outputFile)
        {
            string outPath = outputFile;
            string enc = "encrypted_";
            string dec = "decrypted_";

            if (!File.Exists(inputFile)) throw new FileNotFoundException("inputFile: " + inputFile);

            if (string.IsNullOrEmpty(outputFile))
            {
                string fileName = Path.GetFileName(inputFile);
                string path = Path.GetDirectoryName(inputFile) + Path.DirectorySeparatorChar.ToString();
                if (!Path.IsPathFullyQualified(inputFile))
                    path = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar.ToString();

                outPath = path + (encrypting ? enc : dec) + fileName;
            }
            if (File.Exists(outPath))
            {
                throw new AccessViolationException("outputFile already exists: " + outPath);
            }

            return (inputFile, outPath);
        }

        private static void EncryptDecrypt(
          bool encrypting,
          string inputFile,
          string outputFile,
          byte[] keyBytes,
          byte[] ivBytes)
        {
            Stopwatch stopwatch = Stopwatch.StartNew();
            using (FileStream inputFileStream = File.Open(inputFile, FileMode.Open))
            {
                using (FileStream outputFileStream = File.Open(outputFile, FileMode.Create))
                {
                    Log.Debug(string.Format("File length: --{0}-- kb", (object)(inputFileStream.Length / 1024L)));
                    using (AesCryptoServiceProvider cryptoServiceProvider = new AesCryptoServiceProvider())
                    {
                        cryptoServiceProvider.KeySize = 256;
                        cryptoServiceProvider.BlockSize = 128;
                        cryptoServiceProvider.Padding = PaddingMode.PKCS7;
                        cryptoServiceProvider.Key = keyBytes;
                        cryptoServiceProvider.IV = ivBytes;
                        ICryptoTransform transform = encrypting ? cryptoServiceProvider.CreateEncryptor() : cryptoServiceProvider.CreateDecryptor();
                        using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, transform, CryptoStreamMode.Write))
                        {
                            byte[] buffer = new byte[inputFileStream.Length];
                            inputFileStream.Read(buffer, 0, buffer.Length);
                            cryptoStream.Write(buffer, 0, buffer.Length);
                        }
                    }
                }
            }
            stopwatch.Stop();
            Log.Debug(string.Format("Encryption of file took: {0} ms ~ {1} s", (object)stopwatch.ElapsedMilliseconds, (object)(stopwatch.ElapsedMilliseconds / 1000L)));
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
    }
}
