namespace Program
{
    using CommandLine;

    /// <summary>
    /// Defines the <see cref="Options" />.
    /// </summary>
    public class Options
    {
        [Option('e', "encrypt", Required = false, Group = "crypt", HelpText = "Encrypt file")]
        public string EncryptFile { get; set; }

        [Option('d', "decrypt", Required = false, Group = "crypt", HelpText = "Decrypt file")]
        public string DecryptFile { get; set; }

        [Option('p', "passphrase", Required = true, HelpText = "Passphrase")]
        public string Passphrase { get; set; }

        [Option('i', "iterations", Required = false, HelpText = "Numer of Pbkdf2-HMACSHA512 iterations while deriving key from password - more is better. Min/default value 100 000")]
        public int Iterations { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "Set verbose output")]
        public bool Verbose { get; set; }
    }
}
