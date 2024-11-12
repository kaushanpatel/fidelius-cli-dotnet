using ABDMEncryptionTest.Models;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Mvc;


namespace ABDMEncryptionTest.Controllers
{
    public class KeysController : Controller
    {
        // GET: Keys
        [HttpGet]
        public ActionResult Generate()
        {
            var keyPair = GenerateKeyPair();
            var receiverPrivateKey = GetBase64String(GetEncodedPrivateKey(keyPair.Private));
            var receiverPublicKey = GetBase64String(GetEncodedPublicKey(keyPair.Public));
            var receiverX509PublicKey = GenerateX509PublicKey(keyPair.Public);
            var receiverNonce = GenerateRandomKey();
            var keyMaterial = new KeyMaterial(receiverPrivateKey, receiverPublicKey, receiverNonce, receiverX509PublicKey);
            return Json(keyMaterial, JsonRequestBehavior.AllowGet);
        }

        private string GenerateX509PublicKey(AsymmetricKeyParameter publicKey)
        {
            var ecPublicKeyParameters = (ECPublicKeyParameters)publicKey;
            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ecPublicKeyParameters);
            var asn1PublicKey = subjectPublicKeyInfo.ToAsn1Object();
            var publicKeyBytes = asn1PublicKey.GetEncoded();

            return GetBase64String(publicKeyBytes);
        }

        private AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var generator = new ECKeyPairGenerator();
            var ecParams = CustomNamedCurves.GetByName("curve25519");
            var keyGenParams = new ECKeyGenerationParameters(new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H), new SecureRandom());

            generator.Init(keyGenParams);
            return generator.GenerateKeyPair();
        }

        private string GetBase64String(byte[] value)
        {
            return Convert.ToBase64String(value);
        }

        private byte[] GetEncodedPrivateKey(AsymmetricKeyParameter privateKey)
        {
            var ecPrivateKeyParameters = (ECPrivateKeyParameters)privateKey;
            return ecPrivateKeyParameters.D.ToByteArray();
        }

        private byte[] GetEncodedPublicKey(AsymmetricKeyParameter publicKey)
        {
            var ecPublicKeyParameters = (ECPublicKeyParameters)publicKey;
            return ecPublicKeyParameters.Q.GetEncoded(false);
        }

        private string GenerateRandomKey()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }
            return Convert.ToBase64String(random);
        }

    }
}