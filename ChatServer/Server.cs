using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ChatServer
{
    public class Server
    {
        public const int poort = 1111;
        public Dictionary<IPEndPoint, string> clients = new Dictionary<IPEndPoint, string>(); // clients ip naar naam
        public Dictionary<IPEndPoint, string> pubkeys = new Dictionary<IPEndPoint, string>(); // public key per client
        public Dictionary<IPEndPoint, byte[]> clientAesKeys = new Dictionary<IPEndPoint, byte[]>(); // aes-keys per client
        public string sendablePubServerString;
        RSA rSA;
        Aes _aes;

        byte[] hmac;
        byte[] makeHmac(byte[] key, byte[] encryptedMessage)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(encryptedMessage);
            }
        }

        #region Encryption
        public void EncryptionBootUp()
        {
            RSA rsa = RSA.Create();
            RSAParameters publicKeyInfo = rsa.ExportParameters(false);
            RSAParameters privateKeyInfo = rsa.ExportParameters(true);

            string sendablePub = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());
            sendablePubServerString = sendablePub;
            rSA = rsa;

            Aes aes = Aes.Create();
            _aes = aes;
            Console.WriteLine($"RSA key size: {rSA.KeySize} bits");
        }
        #endregion

        public void RegisterClient(IPEndPoint ep, string message, UdpClient udp)
        {
            string[] parts = message.Split("|");
            string naam = parts[0].Substring(9);
            string pubKey = parts[1];
            if (message.StartsWith("REGISTER:"))
            {
                if (!clients.ContainsKey(ep))
                {
                    clients.Add(ep, naam);
                    pubkeys.Add(ep, pubKey);
                    BroadCastMessageToIP(ep, $"{naam} is de chat gejoined", udp);
                }
                else
                {
                    clients[ep] = naam;
                }
            }
        }


        public void DeleteClient(IPEndPoint ep, string message, UdpClient udp)
        {
            if (message.StartsWith("LEAVE") && clients.ContainsKey(ep))
            {
                string naam = clients[ep];
                byte[] temp = Encoding.UTF8.GetBytes($"{naam} is de chat geleaved");

                foreach (var client in clients)
                {
                    if (!client.Key.Equals(ep))
                    {
                        udp.Send(temp, temp.Length, client.Key);
                    }
                }

                clients.Remove(ep);
                pubkeys.Remove(ep);
                clientAesKeys.Remove(ep); // verwijder AES-sleutel bij disconnect
            }
        }

        
        public void BroadCastMessageToIP(IPEndPoint ep, string message, UdpClient udp)
        {
            string naam = clients[ep];
            string fullMessage = $"{naam}: {message}";
            byte[] plainBytes = Encoding.UTF8.GetBytes(fullMessage);

            foreach (var client in clients)
            {
                if (client.Key.Equals(ep)) continue;
                if (!clientAesKeys.ContainsKey(client.Key)) continue;

                byte[] clientKey = clientAesKeys[client.Key];

                using (Aes aes = Aes.Create())
                {
                    aes.Key = clientKey;
                    aes.GenerateIV();

                    byte[] encryptedMessage = aes.EncryptCbc(plainBytes, aes.IV, PaddingMode.PKCS7);
                    byte[] ivAndEncrypted = aes.IV.Concat(encryptedMessage).ToArray();

                    byte[] hmac = makeHmac(clientKey, ivAndEncrypted);
                    byte[] sendableTemp = hmac.Concat(ivAndEncrypted).ToArray();

                    udp.Send(sendableTemp, sendableTemp.Length, client.Key);
                }
            }
        }

        public void StartListening()
        {
            UdpClient udpClient = new UdpClient(poort);
            IPEndPoint iPEndPoint = new IPEndPoint(IPAddress.Any, poort);

            try
            {
                Console.WriteLine("Server is opgestart");
                while (true)
                {
                    byte[] KeyCheck = udpClient.Receive(ref iPEndPoint);
                    string KeyCheck1 = Encoding.UTF8.GetString(KeyCheck);
                    if (KeyCheck1 == "KEY")
                    {
                        byte[] sendablePubServer = Encoding.UTF8.GetBytes(sendablePubServerString);
                        udpClient.Send(sendablePubServer, sendablePubServer.Length, iPEndPoint);
                        continue;
                    }

                    // decrypten ontvangen bericht 
                    byte[] encryptedBytesFull = KeyCheck;
                    byte[] encryptedAesKey = encryptedBytesFull.Take(256).ToArray();
                    byte[] encryptedAesMessageAndHmac = encryptedBytesFull.Skip(256).ToArray();

                    // Hmac 
                    byte[] receivedHmac = encryptedAesMessageAndHmac.Skip(encryptedAesMessageAndHmac.Length - 32).ToArray();
                    // AES-message 
                    byte[] encryptedAesMessage = encryptedAesMessageAndHmac.Take(encryptedAesMessageAndHmac.Length - 32).ToArray();

                    byte[] decryptedAesKeyAndIv = rSA.Decrypt(encryptedAesKey, RSAEncryptionPadding.Pkcs1);
                    byte[] aesKey = decryptedAesKeyAndIv.Take(32).ToArray(); // de sleutel
                    byte[] aesIv = decryptedAesKeyAndIv.Skip(32).Take(16).ToArray(); // de IV
                    byte[] decryptedAesMessage;

                    // Hmac check
                    using (var hmacCheck = new HMACSHA256(aesKey))
                    {
                        byte[] calculatedHmac = hmacCheck.ComputeHash(encryptedAesKey.Concat(encryptedAesMessage).ToArray());
                        if (!calculatedHmac.SequenceEqual(receivedHmac))
                        {
                            Console.WriteLine("Het ontvangen bericht was aangepast");
                            byte[] clientTamper = Encoding.UTF8.GetBytes("Uw bericht was aangepast, " +
                                "gebeurd dit bij het registreren doe dit met hetzelfde commando opnieuw," +
                                "Als dit bij een normaal bericht gebeurd stuur het bericht dan opnieuw");

                            udpClient.Send(clientTamper, clientTamper.Length, iPEndPoint);
                            continue;
                        }
                        else
                        {
                            using (Aes aesTemp = Aes.Create())
                            {
                                aesTemp.Key = aesKey;
                                aesTemp.IV = aesIv;
                                aesTemp.Mode = CipherMode.CBC;
                                aesTemp.Padding = PaddingMode.PKCS7;
                                decryptedAesMessage = aesTemp.DecryptCbc(encryptedAesMessage, aesIv, PaddingMode.PKCS7);
                            }
                        }
                    }

                    // sla AES-sleutel op per client
                    if (!clientAesKeys.ContainsKey(iPEndPoint))
                    {
                        clientAesKeys[iPEndPoint] = aesKey;
                    }

                    string message = Encoding.UTF8.GetString(decryptedAesMessage);
                    Console.WriteLine($"Received broadcast from {iPEndPoint} :");

                    // FIX: stuur nu string ipv byte[]
                    if (message.StartsWith("REGISTER"))
                    {
                        RegisterClient(iPEndPoint, message, udpClient);
                    }
                    else if (message.StartsWith("LEAVE"))
                    {
                        DeleteClient(iPEndPoint, message, udpClient);
                    }
                    else
                    {
                        BroadCastMessageToIP(iPEndPoint, message, udpClient);
                    }
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                Console.WriteLine("Server wordt afgesloten");
                udpClient.Close();
            }
        }
    }
}
