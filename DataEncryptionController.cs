using System;
using System.Linq;
using System.Web.Mvc;
using ABDMEncryptionTest.Models;
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
    public class DataEncryptionController : Controller
    {
        [HttpPost]
        public ActionResult Encrypt(EncryptionRequest encryptionRequest)
        {
            var xorOfRandom = XorOfRandom(encryptionRequest.SenderNonce, encryptionRequest.ReceiverNonce);
            var encryptedData = EncryptData(xorOfRandom, encryptionRequest.SenderPrivateKey, encryptionRequest.ReceiverPublicKey, encryptionRequest.PlainTextData);            
            var response = new EncryptionResponse(encryptedData);
            return Json(response);
        }

        private byte[] XorOfRandom(string senderNonce, string receiverNonce)
        {
            var randomSender = Base64.Decode(senderNonce);
            var randomReceiver = Base64.Decode(receiverNonce);
            return randomSender.Zip(randomReceiver, (s, r) => (byte)(s ^ r)).ToArray();
        }

        private string EncryptData(byte[] xorOfRandom, string senderPrivateKey, string receiverPublicKey, string plainTextData)
        {
            var sharedKey = DoECDH(Base64.Decode(senderPrivateKey), Base64.Decode(receiverPublicKey));
            var iv = xorOfRandom.Skip(xorOfRandom.Length - 12).ToArray();
            var aesKey = GenerateAesKey(xorOfRandom, sharedKey);
            return AesGcmEncrypt(aesKey, iv, plainTextData);
        }

        private string DoECDH(byte[] senderPrivateKey, byte[] receiverPublicKey)
        {           
            var curve = CustomNamedCurves.GetByName("curve25519");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var privateKeyParams = new ECPrivateKeyParameters(new BigInteger(senderPrivateKey), domainParams);
            var publicKeyParams = new ECPublicKeyParameters(curve.Curve.DecodePoint(receiverPublicKey), domainParams);

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

        private string AesGcmEncrypt(byte[] key, byte[] iv, string plainText)
        {
            var plainBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv, null);
            cipher.Init(true, parameters);
            var encryptedBytes = new byte[cipher.GetOutputSize(plainBytes.Length)];
            var len = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, encryptedBytes, 0);
            cipher.DoFinal(encryptedBytes, len);
            return Convert.ToBase64String(encryptedBytes);
        }
    }
}