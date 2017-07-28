using Newtonsoft.Json;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;

namespace OAuth.Pack
{
    public class RSAUtil
    {
        private const int RsaKeySize = 2048;
        private const string publicKeyFileName = "RSA.Pub";
        private const string privateKeyFileName = "RSA.Private";
        /// <summary>
        /// 从本地文件中读取用来签发 Token 的 RSA Key
        /// </summary>
        /// <param name="filePath">存放密钥的文件夹路径</param>
        /// <param name="withPrivate">私人</param>
        /// <param name="keyParameters">RSA秘钥</param>
        /// <returns></returns>
        public static bool TryGetKeyParameters(string filePath, bool withPrivate, out RSAParameters keyParameters)
        {
            string filename = withPrivate ? privateKeyFileName : publicKeyFileName;
            keyParameters = default(RSAParameters);
            var path = Path.Combine(filePath, filename);
            if (!File.Exists(path))
                return false;
            var rsaXml = File.ReadAllText(path);
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(rsaXml);
                keyParameters = rsa.ExportParameters(withPrivate);
            }
            return true;
        }

        public static bool TryGetKeyParameters(string filePath, bool withPrivate, out RSA rsa)
        {
            string filename = withPrivate ? privateKeyFileName : publicKeyFileName;
            rsa = default(RSA);
            var path = Path.Combine(filePath, filename);
            if (!File.Exists(path))
                return false;
            var rsaXml = File.ReadAllText(path);
            rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(rsaXml);
            return true;
        }
        /// <summary>
        /// 生成并保存 RSA 公钥与私钥
        /// </summary>
        /// <param name="filePath">存放密钥的文件夹路径</param>
        /// <returns></returns>
        public static RSAParameters GenerateAndSaveKey(string filePath)
        {
            RSAParameters privateKeys;
            string publicKeysStr, privateKeysStr;
            using (var rsa = new RSACryptoServiceProvider(RsaKeySize))
            {
                try
                {
                    privateKeys = rsa.ExportParameters(true);
                    privateKeysStr = rsa.ToXmlString(true);
                    publicKeysStr = rsa.ToXmlString(false);
                }
                finally
                {
                    //该值指示是否应在加密服务提供程序 (CSP) 中保留此密钥。
                    rsa.PersistKeyInCsp = false;
                }
            }
            File.WriteAllText(Path.Combine(filePath, privateKeyFileName), privateKeysStr);
            File.WriteAllText(Path.Combine(filePath, publicKeyFileName), publicKeysStr);
            return privateKeys;
        }
    }
}
