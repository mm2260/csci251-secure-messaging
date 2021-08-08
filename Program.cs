/* <author> Mohammed Mehboob (mm2260@rit.edu) </author>

<summary>
Submission for CSCI-251: Concepts of Parallel and Distributed Systems @ RIT,
Project-3: Secure Messaging

Program to send and receive secure message by utilizing RSA encryption.
</summary>

*/

using System;
using System.Threading.Tasks;

namespace Messenger
{
    /// <summary>
    /// The Program class acts as the driver class for the messsenger program,
    /// containing the main function within it.
    /// </summary>
    static class Program
    {
        /// <summary>
        /// Prints usage to standard output.
        /// </summary>
        static void Usage()
        {
            Console.WriteLine(@"Usage:
* keyGen <keysize>
* sendKey <email>
* getKey <email>
* sendMsg <email> <message>
* getMsg <email>");
        }

        /// <summary>
        /// The Main function:
        /// it is async because it utilizes other async function, and thus must wait for them.
        /// </summary>
        static async Task Main(string[] args)
        {

            if( args.Length == 0 ) {
              Console.WriteLine("Incorrect Parameters!");
              Usage();
              return;
            }

            Messenger messenger = new Messenger();
            String email = null;

            var opt = args[0];
            switch (opt)
            {
                case "keyGen":

                    if( args.Length != 2 )  //< {keyGen} {key-size}
                    {
                        Console.WriteLine("Incorrect Parameters!");
                        Usage();
                        return;
                    }

                    var keysize = int.Parse(args[1]);

                    if( keysize < 0 ) {
                      Console.WriteLine("Keysize needs to be positive!");
                      return;
                    }

                    messenger.GenerateKeys(keysize);
                    break;

                case "sendKey":

                    if( args.Length != 2 )  //< {sendKey} {email}
                    {
                        Console.WriteLine("Incorrect Parameters!");
                        Usage();
                        return;
                    }

                    email = args[1];
                    await messenger.SendKey(email);
                    break;

                case "getKey":

                    if( args.Length != 2 )  //< {getKet} {email}
                    {
                        Console.WriteLine("Incorrect Parameters!");
                        Usage();
                        return;
                    }

                    email = args[1];
                    await messenger.GetKey(email);
                    break;

                case "sendMsg":

                    if( args.Length != 3 )  //< {sendMsg} {email} {message}
                    {
                        Console.WriteLine("Incorrect Parameters!");
                        Usage();
                        return;
                    }

                    email = args[1];
                    var plaintext = args[2];
                    await messenger.SendMessage(email, plaintext);
                    break;

                case "getMsg":

                    if( args.Length != 2 )  //< {getMsg} {email}
                    {
                        Console.WriteLine("Incorrect Parameters!");
                        Usage();
                        return;
                    }

                    email = args[1];
                    await messenger.GetMessage(email);
                    break;

                case "help":
                    Usage();
                    break;

                default:
                    Usage();
                    break;
            }
        }

    }
}
