/* <author> Mohammed Mehboob (mm2260@rit.edu) </author>

<summary>
Part of the submission for CSCI-251: Concepts of Parallel and Distributed Systems @ RIT,
Project-3: Secure Messaging.

Initially the submission for CSCI-251: Concepts of Parallel and Distributed Systems @ RIT,
Project-2: Prime Number Generation

Program to generate large prime numbers using the C# parallel library through a brute force approach by generating many
random large numbers and checking for their primality.
</summary>

*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace PrimeGen
{
    /*
     * The PrimeGenerator class
     * The main PrimeGen class
     * Contains the implementation for our prime generation logic
     */
    /// <summary>
    /// This is the Prime number generator class
    /// </summary>
    public class PrimeGenerator
    {
        /// <value>The count of prime numbers to generate.</value>
        private readonly int _target;
        /// <value>The number of bits of the prime number. Must be a multiple of 8 and at least 32.</value>
        private readonly int _bytes;
        /// <summary>Array of primes (up to 200) used to check factors of larger numbers.</summary>
        private readonly int[] _primes;
        /// <summary>Data byte array, used to construct a BigInteger.</summary>
        private readonly byte[] _data;

        private readonly List<BigInteger> _results = new List<BigInteger>();

        /// <summary>static Random Number Generator instance.</summary>
        private static readonly RNGCryptoServiceProvider RngCrypto = new RNGCryptoServiceProvider();

        /// <summary>
        /// The Prime Generator class constructor.
        /// Performs the initialization of internal data array for individual bytes,
        /// and the first 100 (or 200) prime numbers array for larger numbers.
        /// </summary>
        /// <param name="bits">Number of bits of the prime number</param>
        /// <param name="target">Number of prime number to generate</param>
        public PrimeGenerator(int bits, int target)
        {
            this._target = target;
            this._bytes = bits/8;

            if (bits >= 1024)
            {
                this._primes = bits > 4096 ? GeneratePrimesUpTo(200).ToArray() : GeneratePrimesUpTo(100).ToArray();
            }

            //BigInteger expects data to be in little-endian order, therefore appending a 00 byte at the end of the
            //byte array makes sure that the resultant bigInt is positive.
            this._data = new byte[_bytes].Concat(new byte[] {0}).ToArray();

        }

        /// <summary>
        /// The generator's main execution loop.
        /// Generate random big integers of size specified in the constructor and spawn a thread for each to check for
        /// its primality. Stop further processing once the target number of primes have been generated.
        /// </summary>
        public List<BigInteger> Execute()
        {
            var found = 0;  //< keep track of how many prime number have been generated so far.

            var tasks = new List<Task>();
            var tokenSource = new CancellationTokenSource();    //< Source for cancellation token
            var token = tokenSource.Token;                      //< Cancellation token, so we can stop all threads once
                                                                //  the target number of primes have been generated.

            while (found < _target)
            {
                var bigInt = GenerateRandomBigInt();

                tasks.Add(Task.Run(() =>
                    {
                        var capturedBigInt = bigInt;    //< capture generated BigInt.

                        //If our number is large, try checking up to the first 100 (or 200) primes for divisibility.
                        if (_bytes >= 128)
                        {
                            //remark: I observed that the iterative loop, on average, gave better results than a
                            //        <collection>.Any( <var> => <condition> ) LINQ query.
                            foreach (var prime in _primes)
                            {
                                if (capturedBigInt % prime == 0) //< If the BigInt is divisible by one of the primes,
                                    return;                        //  then we simply stop and don't check further.
                            }
                        }

                        if (capturedBigInt.IsProbablyPrime())   //Long running check function.
                        {
                            if (!token.IsCancellationRequested) //< Poll our cancellation token to check if we need to
                                                                //  stop further processing.
                            {

                                var newFound = Interlocked.Increment(ref found);    //< Atomic increment.
                                if (newFound == _target)
                                    tokenSource.Cancel();   //< Signal other threads to cancel.

                                // Console.WriteLine($"{found}: {capturedBigInt}");    //< Print prime number to console.
                                _results.Add(capturedBigInt);
                            }
                        }

                    }, token)
                );
            }

            //Prevent elapsed time to print before all the primes have been printed out to the console.
            Task.WhenAll(tasks.ToArray()).ContinueWith( t => { },
            TaskContinuationOptions.OnlyOnCanceled).Wait();

            return _results;
        }

        /// <summary>
        /// Generate a random BigInt of size equal to the number of bits specified in the generator's constructor.
        /// </summary>
        /// <returns>BigInt with size ($_bytes) bits</returns>
        private BigInteger GenerateRandomBigInt()
        {
            RngCrypto.GetBytes(_data, 0, _bytes );  //< only generates ${_bytes} bytes,
            //  not disturbing the last 00 byte in our array.
            return new BigInteger(_data);
        }

        /// <summary>
        /// Method that generates all the prime numbers up to 'n' in parallel.
        /// </summary>
        /// <param name="n">Upper bound for the prime numbers generated</param>
        /// <returns>List of prime numbers up to 'n'</returns>
        /// <remarks>
        /// Referenced user spookycoder's solution from stackoverflow.
        /// https://stackoverflow.com/questions/1042902/most-elegant-way-to-generate-prime-numbers
        /// </remarks>
        private List<int> GeneratePrimesUpTo( int n) {
            var r = from i in Enumerable.Range(2, n - 1).AsParallel()
                where Enumerable.Range(1, (int)Math.Sqrt(i)).All(j => j == 1 || i % j != 0)
                select i;
            return r.ToList();
        }

    }

    public static class Extensions
    {
        /// <summary>
        /// Extension method for an implementation of the Miller-Rabin primality test.
        /// </summary>
        /// <param name="value">value to be checked for primality</param>
        /// <param name="witnesses">witness loop iterations</param>
        /// <returns>boolean value for the value passed being a prime number</returns>
        public static Boolean IsProbablyPrime(this BigInteger value, int witnesses = 10)
        {
            if (value <= 1) return false;

            if (witnesses <= 0) witnesses = 10;

            BigInteger d = value - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            var bytes = new byte[value.ToByteArray().LongLength];

            for (var i = 0; i < witnesses; i++)
            {
                BigInteger a;
                do
                {
                    var gen = new Random();
                    gen.NextBytes(bytes);
                    a = new BigInteger(bytes);
                } while (a < 2 || a >= value - 2);

                var x = BigInteger.ModPow(a, d, value);
                if( x==1 || x==value-1) continue;

                for (var r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, value);
                    if (x == 1) return false;
                    if (x == value - 1) break;
                }

                if (x != value - 1) return false;

            }

            return true;
        }
    }

}
