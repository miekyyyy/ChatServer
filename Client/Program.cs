using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class Client
{
    static void Main(string[] args)
    {
        #region Encryption
        RSA rsa = RSA.Create();
        string sendablePub = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());

        Aes aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV(); // initieel IV
        byte[] aesKey = aes.Key; // vaste AES-sleutel per sessie
        #endregion

        #region Client
        Console.Write("Registreer je naam met <REGISTER:naam>"); 
        string naam = Console.ReadLine();
        int i = Random.Shared.Next(1112, 12000);

        UdpClient udp = new UdpClient(i);
        IPEndPoint serverEP = new IPEndPoint(IPAddress.Loopback, 1111);

        byte[] makeHmac(byte[] key, byte[] data)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }
       
        // Stap 0: server public key opvragen
        byte[] keyBytes = Encoding.UTF8.GetBytes("KEY");
        udp.Send(keyBytes, keyBytes.Length, serverEP);
        IPEndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
        byte[] serverPubKeyResponse = udp.Receive(ref remoteEP);
        string serverPubKey = Encoding.UTF8.GetString(serverPubKeyResponse);
        byte[] serverKeyBytes = Convert.FromBase64String(serverPubKey);
        RSA rsaServer = RSA.Create();
        rsaServer.ImportSubjectPublicKeyInfo(serverKeyBytes, out _);

        // Stap 1: registreer
        byte[] keyAndIv = aes.Key.Concat(aes.IV).ToArray(); 
        byte[] registerBytes = Encoding.UTF8.GetBytes($"{naam}|{sendablePub}");
        byte[] encryptedBytes = aes.EncryptCbc(registerBytes, aes.IV, PaddingMode.PKCS7);
        byte[] rsaEncryptedAesKey = rsaServer.Encrypt(keyAndIv, RSAEncryptionPadding.Pkcs1);
        byte[] registerMessage = rsaEncryptedAesKey.Concat(encryptedBytes).ToArray();
        byte[] hmac = makeHmac(aes.Key, registerMessage);
        byte[] fullRegisterMessage = registerMessage.Concat(hmac).ToArray();
        udp.Send(fullRegisterMessage, fullRegisterMessage.Length, serverEP);

        // Stap 2: ontvang thread
        Thread receiveThread = new Thread(() =>
        {
            IPEndPoint remoteEP2 = new IPEndPoint(IPAddress.Any, 0);
            while (true)
            {
                byte[] data = udp.Receive(ref remoteEP2);
                if (data.Length < 48) continue; // minimaal HMAC + IV + iets

                byte[] receivedHmac = data.Take(32).ToArray();
                byte[] ivAndEncrypted = data.Skip(32).ToArray();

                byte[] calculatedHmac = makeHmac(aesKey, ivAndEncrypted);
                if (!calculatedHmac.SequenceEqual(receivedHmac))
                {
                    Console.WriteLine("Het ontvangen bericht was aangepast!");
                    continue;
                }

                byte[] iv = ivAndEncrypted.Take(16).ToArray();
                byte[] encryptedMessage = ivAndEncrypted.Skip(16).ToArray();

                string realMessage;
                using (Aes aesDecrypt = Aes.Create())
                {
                    aesDecrypt.Key = aesKey;
                    aesDecrypt.IV = iv;
                    aesDecrypt.Mode = CipherMode.CBC;
                    aesDecrypt.Padding = PaddingMode.PKCS7;

                    byte[] decrypted = aesDecrypt.DecryptCbc(encryptedMessage, iv, PaddingMode.PKCS7);
                    realMessage = Encoding.UTF8.GetString(decrypted);
                }

                Console.WriteLine(realMessage);
            }
        });
        receiveThread.IsBackground = true;
        receiveThread.Start();

        // Stap 3: berichten sturen
        while (true)
        {
            string text = Console.ReadLine();

            aes.GenerateIV();
            keyAndIv = aes.Key.Concat(aes.IV).ToArray();

            byte[] sendBytes = Encoding.UTF8.GetBytes(text);
            encryptedBytes = aes.EncryptCbc(sendBytes, aes.IV, PaddingMode.PKCS7);
            rsaEncryptedAesKey = rsaServer.Encrypt(keyAndIv, RSAEncryptionPadding.Pkcs1);
            byte[] message = rsaEncryptedAesKey.Concat(encryptedBytes).ToArray();
            hmac = makeHmac(aes.Key, message);
            byte[] fullmessage = message.Concat(hmac).ToArray();

            udp.Send(fullmessage, fullmessage.Length, serverEP);
            if (text.ToUpper() == "LEAVE") break;
        }

        udp.Close();
        #endregion
    }
}