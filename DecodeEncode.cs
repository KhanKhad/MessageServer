using System.Security.Cryptography;
using System.Text;


namespace MessageServer
{
    public class DecodeEncode
    {
        public string publicKey;
        public string privateKey;
        public DecodeEncode(string _publicKey, string _privateKey)
        {
            privateKey = _privateKey;
            publicKey = _publicKey;
        }
        public string decript(string ToDecrypt)
        {
            try
            {
                RSACryptoServiceProvider RSA_ = new RSACryptoServiceProvider();
                //Create a UnicodeEncoder to convert between byte array and string.
                UnicodeEncoding ByteConverter = new UnicodeEncoding();

                //Create byte arrays to hold original, encrypted, and decrypted data.
                byte[] Todecrypt = StringToBytes(ToDecrypt);
                byte[] Decrypted;

                RSA_.FromXmlString(privateKey);

                Decrypted = RSADecrypt(Todecrypt, RSA_.ExportParameters(true), false);

                byte[] _Decrypted = new byte[Decrypted.Length / 2];//херня почему-то после каждого байта вставляет ноль
                for (int i = 0; i < Decrypted.Length; i += 2)
                {
                    _Decrypted[i / 2] = Decrypted[i];
                }
                return Encoding.UTF8.GetString(_Decrypted);

            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("Decryption failed.");
                return null;
            }
        }
        public static string encript(string ID, string PersonKey)
        {
            string? Eid;
            try
            {
                RSACryptoServiceProvider RSA_ = new RSACryptoServiceProvider();
                RSA_.FromXmlString(PersonKey);
                UnicodeEncoding ByteConverter = new UnicodeEncoding();
                byte[] IdToEncode = ByteConverter.GetBytes(ID);
                byte[] EncodedId;
                EncodedId = RSAEncrypt(IdToEncode, RSA_.ExportParameters(false), false);
                Eid = BytesToString(EncodedId);
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("Encryption failed.");
                Eid = null;
            }
            return Eid;
        }
        public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }
        public static byte[] StringToBytes(string toEncrypt)
        {
            var a = toEncrypt.Split("|");
            byte[] b = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                b[i] = byte.Parse(a[i]);
            }
            return b;
        }
        public static string BytesToString(byte[] decrypted)
        {
            string a = "";
            foreach (byte b in decrypted)
            {
                a += b + "|";
            }
            return a.TrimEnd('|');
        }
        public static string CreateMD5(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }
}
