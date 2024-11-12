using System;
using System.Linq;
using System.Web.Mvc;
using ABDMEncryptionTest.Models;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace ABDMEncryptionTest.Controllers
{
    public class DataDecryptionController : Controller
    {
        [HttpPost]
        public ActionResult Decrypt(DecryptionRequest decryptionRequest)
        {
            var xorOfRandom = XorOfRandom(decryptionRequest.SenderNonce, decryptionRequest.ReceiverNonce);
            var decryptedData = DecryptData(xorOfRandom, decryptionRequest.ReceiverPrivateKey, decryptionRequest.SenderPublicKey, decryptionRequest.EncryptedData);
            var response = new DecryptionResponse(decryptedData);
            return Json(response);
        }

        private byte[] XorOfRandom(string senderNonce, string receiverNonce)
        {
            var randomSender = Base64.Decode(senderNonce);
            var randomReceiver = Base64.Decode(receiverNonce);
            return randomSender.Zip(randomReceiver, (s, r) => (byte)(s ^ r)).ToArray();
        }

        private string ConverX509toEC(string base64EncodedPublicKeyInfo)
        {
            byte[] publicKeyInfoBytes = Convert.FromBase64String(base64EncodedPublicKeyInfo);            
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(publicKeyInfoBytes);
            byte[] publicKeyBytes = subjectPublicKeyInfo.PublicKeyData.GetBytes();
            string base64EncodedPublicKey = Convert.ToBase64String(publicKeyBytes);
            return base64EncodedPublicKey;
        }

        private string DecryptData(byte[] xorOfRandom, string receiverPrivateKey, string senderPublicKey, string encryptedData)
        {
            if (senderPublicKey.Length > 88)
            {
                senderPublicKey = ConverX509toEC(senderPublicKey);
            }
            var sharedKey = DoECDH(Base64.Decode(receiverPrivateKey), Base64.Decode(senderPublicKey));
            var iv = xorOfRandom.Skip(xorOfRandom.Length - 12).ToArray();
            var aesKey = GenerateAesKey(xorOfRandom, sharedKey);
            return AesGcmDecrypt(aesKey, iv, encryptedData);
        }

        private string DoECDH(byte[] receiverPrivateKey, byte[] senderPublicKey)
        {
            var curve = CustomNamedCurves.GetByName("curve25519");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var privateKeyParams = new ECPrivateKeyParameters(new BigInteger(receiverPrivateKey), domainParams);
            var publicKeyParams = new ECPublicKeyParameters(curve.Curve.DecodePoint(senderPublicKey), domainParams);

            var agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            agreement.Init(privateKeyParams);
            var sharedSecret = agreement.CalculateAgreement(publicKeyParams);
            return Convert.ToBase64String(sharedSecret.ToByteArray());
        }

        private byte[] GenerateAesKey(byte[] xorOfRandom, string sharedKey)
        {
            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(Base64.Decode(sharedKey), xorOfRandom.Take(20).ToArray(), null));
            var aesKey = new byte[32];
            hkdf.GenerateBytes(aesKey, 0, 32);
            return aesKey;
        }

        private string AesGcmDecrypt(byte[] key, byte[] iv, string encryptedData)
        {
            var encryptedBytes = Base64.Decode(encryptedData);
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);
            cipher.Init(false, parameters);
            var decryptedBytes = new byte[cipher.GetOutputSize(encryptedBytes.Length)];
            var len = cipher.ProcessBytes(encryptedBytes, 0, encryptedBytes.Length, decryptedBytes, 0);
            cipher.DoFinal(decryptedBytes, len);
            return System.Text.Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}