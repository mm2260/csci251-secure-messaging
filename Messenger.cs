/* <author> Mohammed Mehboob (mm2260@rit.edu) </author>

<summary>
Submission for CSCI-251: Concepts of Parallel and Distributed Systems @ RIT,
Project-3: Secure Messaging

Program to send and receive secure message by utilizing RSA encryption.
</summary>
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PrimeGen;

namespace Messenger
{

    /*
        The Messenger class.
        Handles all the secure-messaging related functionality:
        - generating keys
        - sending user's public key to server
        - receiving other users' public keys.
        - encrypting messages using RSA
        - decrypting encrypted messages
     */
    /// <summary>
    /// The Messenger Class.
    /// Contains implementations for all secure-messaging related functions.
    /// </summary>
    public class Messenger
    {
        /// <summary>
        /// The currently loaded public key
        /// </summary>
        private PublicKey _publicKey;
        /// <summary>
        /// The currently loaded private key
        /// </summary>
        private PrivateKey _privateKey;
        /// <summary>
        /// HTTP Client, to perform GET and PUT requests.
        /// </summary>
        private static readonly HttpClient Client = new HttpClient();

        /// <summary>
        /// The Messenger Constructor:
        /// Loads public and private keys into memory if the exists on the local file-system.
        /// </summary>
        public Messenger()
        {
            if (!File.Exists("public.key") || !File.Exists("private.key")) return;
            this._publicKey = PublicKey.LoadFromFile("public.key");
            this._privateKey = PrivateKey.LoadFromFile("private.key");
        }

        /// <summary>
        /// Send the public key you generated in the key-gen phase to the server
        /// </summary>
        /// <param name="email">The email to register with your public key on the server</param>
        /// <returns>Task to await for a success response from the server</returns>
        public async Task SendKey(string email)
        {
            // Check if the keys have been generated beforehand:
            if(File.Exists("public.key") && File.Exists("private.key"))
            {
                _publicKey.email = email;   //< update public key email.
                var publicKeyJsonObject = JObject.FromObject(_publicKey);

                // Send our public key to the server.
                var content = new StringContent(publicKeyJsonObject.ToString(), Encoding.UTF8, "application/json");
                var response = await Client.PutAsync($"http://--server-address--/Key/{email}", content);

                // Make sure the key reached successfully.
                if (response.EnsureSuccessStatusCode().IsSuccessStatusCode)
                {
                    Console.WriteLine("Key saved");
                    // Update the private key's email list:
                    if (!_privateKey.emails.Contains(email))
                    {
                        _privateKey.emails.Add(email);
                    }

                    // Save keys to file:
                    _publicKey.SaveToFile("public.key");
                    _privateKey.SaveToFile("private.key");
                }
            }
            else
            {
                Console.WriteLine("No keys found! Please generate keys first.");
            }
        }

        /// <summary>
        /// Get the public key registered with a specific email from the server
        /// </summary>
        /// <param name="email">The email who's public key you want to get</param>
        /// <returns>Task to await for a success response from the server</returns>
        public async Task GetKey(string email)
        {
            // Get response from server:
            var response = await Client.GetAsync(
                $"http://--server-address--/Key/{email}" );
            response.EnsureSuccessStatusCode();

            // Get the content from the response message:
            var keyJObject = JObject.Parse(await response.Content.ReadAsStringAsync());

            PublicKey publicKey = new PublicKey
            {
                key = keyJObject.GetValue("key")?.ToString(),
                email = keyJObject.GetValue("email")?.ToString()
            };

            // Save the received public key to file:
            publicKey.SaveToFile($"{email}.key");
        }

        /// <summary>
        /// Encrypt the plaintext message using the public key associated with an email and sent it to that email.
        /// </summary>
        /// <param name="email">the email to which the message will be sent</param>
        /// <param name="plaintext">The plaintext message you want to send</param>
        /// <returns>Task to await for a success response from the server</returns>
        public async Task SendMessage(string email, string plaintext)
        {
            // Ensure you have the public key for the user you're sending a message to.
            if(!File.Exists($"{email}.key"))
            {
                Console.WriteLine($"Key does not exists for {email}");
            }
            else
            {
                // Get key parameters to perform the RSA encryption:
                var publicKey = PublicKey.LoadFromFile($"{email}.key");
                var keyParameters = ExtractKeyParameters(publicKey.key);

                // Encrypt plaintext:
                var plaintextBigInt = new BigInteger(Encoding.UTF8.GetBytes(plaintext));
                var E = keyParameters.P;
                var N = keyParameters.N;
                var ciphertextBigInt = BigInteger.ModPow(plaintextBigInt, E, N);

                // Convert the ciphertext byte-array to a Base-64 encoded string.
                var ciphertext = Convert.ToBase64String(ciphertextBigInt.ToByteArray());

                var message = new Message { email = email, content = ciphertext };
                // Load message object into a JObject
                var jsonObject = JObject.FromObject(message);

                // Send message to server
                var content = new StringContent(jsonObject.ToString(), Encoding.UTF8, "application/json");
                var response = await Client.PutAsync($"http://--server-address--/Message/{email}", content);

                if (response.EnsureSuccessStatusCode().IsSuccessStatusCode)
                {
                    Console.WriteLine("Message written");
                }
            }
        }

        /// <summary>
        /// Get the encrypted message saved for the specified email from the server, and attempt to decrypt it.
        /// </summary>
        /// <param name="email"></param>
        /// <returns>Task to ensure a success response from the server</returns>
        public async Task GetMessage(string email)
        {
            // Validate that you have the private key for the email being requested:
            if (!_privateKey.emails.Contains(email))
            {
                Console.WriteLine("No compatible private key found. Message can't be decoded.");
            }
            else
            {
                // Get message response from the server:
                var response = await Client.GetAsync(
                    $"http://--server-address--/Message/{email}");
                response.EnsureSuccessStatusCode();

                // Get the content property of the message:
                var ciphertext = JsonConvert.DeserializeObject<Message>(
                    await response.Content.ReadAsStringAsync())?.content;

                // Decrypt received message:
                var keyParameters = ExtractKeyParameters(_privateKey.key);
                var D = keyParameters.P;
                var N = keyParameters.N;

                var ciphertextBigInt = new BigInteger(Convert.FromBase64String(ciphertext!));
                var plaintextBigInt = BigInteger.ModPow(ciphertextBigInt, D, N);

                var plaintext = Encoding.UTF8.GetString(plaintextBigInt.ToByteArray());

                // Print decrypted message:
                Console.WriteLine($"{plaintext}");
            }
        }

        /// <summary>
        /// Generate an RSA public-private key-pair of specified size & save it to the local file-system.
        /// </summary>
        /// <param name="keysize"></param>
        public void GenerateKeys(int keysize)
        {
            //========= generate key parameters ===============

            var primes = new PrimeGenerator(keysize / 2, 2).Execute();

            // Generated two prime numbers, p & q:
            var p = primes[0];
            var q = primes[1];

            // Compute nonce:
            var N = p * q;
            var r = (p - 1) * (q - 1); //< phi(N)

            // Compute E & D:
            var E = new PrimeGenerator(16, 1).Execute()[0];
            var D = ModInverse(E, r);

            //======== generate keys in proper format ===========

            var e = BitConverter.GetBytes(E.GetByteCount());
            var d = BitConverter.GetBytes(D.GetByteCount());
            var n = BitConverter.GetBytes(N.GetByteCount());

            // make sure that eeee, dddd, and nnnn are in big-endian.
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(e);
                Array.Reverse(d);
                Array.Reverse(n);
            }

            // Construct byte-arrays for our keys:
            // E, D, and N are BigIntegers, and so, their byte-arrays are in little endian.
            var publicKeyByteArray = e.Concat(E.ToByteArray()).Concat(n).Concat(N.ToByteArray()).ToArray();
            var privateKeyByteArray = d.Concat(D.ToByteArray()).Concat(n).Concat(N.ToByteArray()).ToArray();

            // Now that we've constructed our byte-arrays, we base-64 encode them and store them locally.
            this._publicKey = new PublicKey { key = Convert.ToBase64String(publicKeyByteArray), email = null };
            _publicKey.SaveToFile("public.key");
            this._privateKey = new PrivateKey { key = Convert.ToBase64String(privateKeyByteArray),
                                                emails = new List<string>() };
            _privateKey.SaveToFile("private.key");

        }

        /// <summary>
        /// Compute the key parameters P & N, where P=E for public keys, and P=D for private keys from a base-64
        /// encoded string representing a key in the form of eeeeEEE...EEEnnnnNN....NN or ddddDDD..DDDnnnnNN...NN.
        /// </summary>
        /// <param name="keyBase64">Base-64 string representing the key</param>
        /// <returns>Tuple of the key-parameters: E/N for public keys, D/N for private keys.</returns>
        private (BigInteger P, BigInteger N) ExtractKeyParameters(string keyBase64)
        {
            // Get the key byte-array from the base-64 encoded string:
            var keyByteArray = Convert.FromBase64String(keyBase64);

            // get first four bytes representing the parameter p (e/d),
            // which gives us the number of bytes in P (E/D):
            var pBytes = keyByteArray.Take(4).ToArray();

            if (BitConverter.IsLittleEndian) { Array.Reverse(pBytes); }   //< p is in big endian.
            var p = BitConverter.ToInt32(pBytes);

            // Read bytes for P and convert it to a BigInteger:
            var P = new BigInteger(keyByteArray.Skip(4).Take(p).ToArray());

            var nBytes = keyByteArray.Skip(4 + p).Take(4).ToArray();

            if (BitConverter.IsLittleEndian) { Array.Reverse(nBytes); }   //< n is in big endian.
            var n = BitConverter.ToInt32(nBytes);

            // Read bytes for N and convert it to a BigInteger:
            var N = new BigInteger(keyByteArray.Skip(4 + p + 4).Take(n).ToArray());

            return (P, N);
        }

        /// <summary>
        /// Calculate the mod inverse
        /// </summary>
        /// <param name="a">a</param>
        /// <param name="n">n</param>
        /// <returns>modulo inverse for (a,n)</returns>
        private static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a>0) {
                BigInteger t = i/a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t*x;
                v = x;
            }
            v %= n;
            if (v<0) v = (v+n)%n;
            return v;
        }

    }


    /*
        The Key abstract class.
        Contains the basic save to file functionality which is common to both, Private and Public keys.
     */
    /// <summary>
    /// Key abstract class, parent class of PublicKey and PrivateKey.
    /// </summary>
    public abstract class Key
    {
        /// <summary>
        ///
        /// </summary>
        public string key;

        /// <summary>
        ///
        /// </summary>
        /// <param name="filename"></param>
        public void SaveToFile(string filename)
        {
            File.WriteAllBytes( $"{filename}", Encoding.UTF8.GetBytes( JsonConvert.SerializeObject(this) ) );
        }
    }


    /*
        The Public Key class.
        Contains an email, for which it encrypts message for.
        Only that email can then decrypt it.
        Extends the common functionality of the Key abstract class with functionality to load from file.
    */
    /// <summary>
    /// RSA Public Key
    /// used for encrypting outgoing messages.
    /// </summary>
    public class PublicKey : Key
    {
        /// <summary>
        /// The email of the user who's public key this is.
        /// </summary>
        public string email;
        /// <summary>
        /// De-serialize the public key data stored in a file.
        /// </summary>
        /// <param name="filename">Loads the public key from the provided filename
        /// {filename MUST INCLUDE EXTENSION}
        /// </param>
        /// <returns>Public Key object from the data stored in {filename}</returns>
        public static PublicKey LoadFromFile(string filename)
        {
            var bytes = File.ReadAllBytes($"{filename}");
            var jsonObject = Encoding.UTF8.GetString(bytes);
            return JsonConvert.DeserializeObject<PublicKey>(jsonObject);
        }
    }


    /*
        The Private Key class.
        Contains a list of emails whose messages it can decrypt.
        Extends the common functionality of the Key abstract class with functionality to load from file.
     */
    /// <summary>
    /// RSA Private Key.
    /// used for decrypting incoming encrypted messages.
    /// </summary>
    public class PrivateKey : Key
    {
        /// <summary>
        /// List of emails that this private key can decrypt messages for.
        /// </summary>
        public List<string> emails;
        /// <summary>
        /// De-serialize the private key data stored in a file.
        /// </summary>
        /// <param name="filename">Loads the private key from the provided filename
        /// {filename MUST INCLUDE EXTENSION}
        /// </param>
        /// <returns>Private Key object from the data stored in {filename}</returns>
        public static PrivateKey LoadFromFile(string filename)
        {
            var bytes = File.ReadAllBytes($"{filename}");
            var jsonObject = Encoding.UTF8.GetString(bytes);
            return JsonConvert.DeserializeObject<PrivateKey>(jsonObject);
        }
    }


    /*
        The Message class.
        Used in serialization for sending messages to server.
     */
    /// <summary>
    /// Class to represent Message Objects.
    /// </summary>
    public class Message
    {
        /// <summary>
        /// Tells the server who the message is for
        /// </summary>
        public string email;
        /// <summary>
        /// Contents of the message
        /// </summary>
        public string content;
    }
}
