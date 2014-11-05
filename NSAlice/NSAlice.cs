using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace NSAlice
{
    class NSAlice
    {
        static void Main(string[] args)
        {
            bool useCBC = true;
            byte[] aliceKey = new byte[] { 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };
            byte[] IV = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 };

            string message = "I want to talk";

            Console.WriteLine("Alice Sends - Alice Wants To Talk");

            // send i want to talk to bob, and recieve his first response
            string bobsFirstMessage = sendMessage(message, 11000, useCBC);

            // get a nonce to use
            string nonce1 = getNonce();

            // create our message for the kdc
            string messageForKDC = nonce1 + "987654321" + bobsFirstMessage;

            Console.WriteLine("Alice sends N1, \"Alice Wants Bob\", Kbob{Nb}");
            // send the message to the kdc
            string kdcResponse = sendMessage(messageForKDC, 12000, useCBC);

            Console.WriteLine("alice recieves kdc response");
            // decrypte the kdc response
            string kdcResponseDecrypted = Decrypt(kdcResponse, aliceKey, IV, useCBC);

            // split the kdc response based on the delimeter
            string[] messageSplits = kdcResponseDecrypted.Split(new string[] { "987654321" }, StringSplitOptions.None);

            // check to make sure the nonce matches
            if(nonce1 != messageSplits[0])
            {
                return;
            }
            // get the shared key from the reponse
            string sharedKey = messageSplits[1];
            
            // ge the ticket from the respojnse
            string ticket = messageSplits[2];

            // get a nonce2 and encrypt it
            Int64 nonce2 = NextInt64();
            string encryptedNonce2 = encryptMessage(getBytes(sharedKey), IV, getBytes(nonce2.ToString()), useCBC);

            //send those things to bob
            Console.WriteLine("Alice sends ticket to bob, along with N2 encrypted by shared key");
            string bobsResponse = sendMessage(ticket + "987654321" + encryptedNonce2, 11001, useCBC);

            // decrypt bobs response
            string bobDecrypted = Decrypt(bobsResponse, getBytes(sharedKey), IV, useCBC);

            // extract the two pieces of bobs response
            string nonce2Minus = bobDecrypted.Substring(0, 32);
            string nonce3 = bobDecrypted.Substring(32, 32);

            Int64 nonce2After;

            // this section is just retriening the 64 bit nonces out of the message
            Int64.TryParse(nonce2Minus, out nonce2After);

            if(nonce2After + 1 != nonce2)
            {
                return;
            }

            Int64 nonce3Minus;

            Int64.TryParse(nonce3, out nonce3Minus);

            nonce3Minus--;

            // alice subtracts 1 from nonce 3 and responds to bob.
            Console.WriteLine("fially alice responds to bob with nonce3 - 1 encrypted by the shared key");
            sendMessage(nonce3Minus.ToString(), 11002, useCBC);

            Console.Read();
        }

        public static string sendMessage(string toSend, int port, bool useCBC)
        {
            // Data buffer for incoming data.
            byte[] bytes = new byte[1024];

            string result = null;

            // Connect to a remote device.
            try
            {

                IPAddress ipAddress = IPAddress.Loopback;
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);

                // Create a TCP/IP  socket.
                Socket sender = new Socket(AddressFamily.InterNetwork,
                    SocketType.Stream, ProtocolType.Tcp);

                // Connect the socket to the remote endpoint. Catch any errors.
                try
                {
                    sender.Connect(remoteEP);

                    // Encode the data string into a byte array.
                    byte[] msg = getBytes(toSend + "<EOF>");
                    

                    // Send the data through the socket.
                    int bytesSent = sender.Send(msg);

                    // Receive the response from the remote device.
                    int bytesRec = sender.Receive(bytes);

                    //result = Encoding.ASCII.GetString(bytes, 0, bytesRec);
                    result = getString(bytes);
                    result = result.Substring(0, result.IndexOf("<EOF>"));
                    // Release the socket.
                    sender.Shutdown(SocketShutdown.Both);
                    sender.Close();

                }
                catch (ArgumentNullException ane)
                {
                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                    return null;
                }
                catch (SocketException se)
                {
                    Console.WriteLine("SocketException : {0}", se.ToString());
                    return null;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
                    return null;
                }


            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return result;
        }

        public static string getNonce()
        {
            Random rnd = new Random();
            byte[] result = new byte[64];
            rnd.NextBytes(result);
            return getString(result);
        }

        public static Int64 NextInt64()
        {
            Random rnd = new Random();
            var buffer = new byte[sizeof(Int64)];
            rnd.NextBytes(buffer);
            return BitConverter.ToInt64(buffer, 0);
        }

        public static string getString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }

        public static byte[] getBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string Decrypt(string cipherBlock, byte[] key, byte[] IV, bool usuCBC)
        {
            byte[] toEncryptArray = getBytes(cipherBlock);

            // Set the secret key for the tripleDES algorithm
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = key;
            tdes.IV = IV;
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.Zeros;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            tdes.Clear();

            // Return the Clear decrypted TEXT
            return getString(resultArray);
        }

        public static string encryptMessage(byte[] key, byte[] IV, byte[] message, bool useCBC)
        {
            byte[] keyBytes = key; // UTF8Encoding.UTF8.GetBytes(key);
            byte[] messageBytes = message;   //UTF8Encoding.UTF8.GetBytes(message);
            byte[] ivBytes = IV; // UTF8Encoding.UTF8.GetBytes(IV);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            tdes.Key = keyBytes;
            tdes.IV = ivBytes;
            if (useCBC)
            {
                tdes.Mode = CipherMode.CBC;
            }
            else
            {
                tdes.Mode = CipherMode.ECB;
            }
            tdes.Padding = PaddingMode.Zeros;

            ICryptoTransform encryptor = tdes.CreateEncryptor();

            byte[] encResult = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

            tdes.Clear();

            string toReturn = getString(encResult);
            byte[] test = getBytes(toReturn);
            return toReturn;

        }
    }
}
