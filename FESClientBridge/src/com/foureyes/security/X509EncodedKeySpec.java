package com.foureyes.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import com.foureyes.exception.DecodeHashException;
import com.foureyes.exception.KeyConvertException;

/**
 * The most important class of this bridge's security session. It's using
 * 512-bit RSA as a encrypting way. Though it's a bit difficult to understand,
 * its security is really quanlified. The keys will be sent in a two-way process
 * between the FES's control cloud and the collaborated server. They use the
 * other's key to lock and their own key to unlock the returned data. So
 * confusing, right ? <br>
 * <b>(Phong: Me toooo :<)</b></br>
 */
public class X509EncodedKeySpec {

	/**
	 * The public RSA key of the collaborate server. The public key will be sent to
	 * FES's control, the control may use it to encode the returned data.
	 */
	private static byte[] LOCAL_PBKEY = {};
	/**
	 * The private RSA key of the collaborate server. This is the most important key
	 * to decode the data received from FES's control cloud.
	 */
	private static byte[] LOCAL_PRKEY = {};
	/**
	 * The public RSA key of the FES's control cloud. This key is received from
	 * cloud, then the bridge may use it to encode data before sending back to FES's
	 * control cloud.
	 */
	private static String CLOUD_PBKEY = "";

	/**
	 * This step will check whether the local public key and the private one are
	 * null or not. If they're null, then check the stored file. If their files
	 * exist, they key will be loaded from these files; otherwise, a new key pair
	 * will be created and stored.
	 */
	public static void generateKey() {
		if (LOCAL_PBKEY == null || LOCAL_PRKEY == null) {
			try {
				SecureRandom sr = new SecureRandom();
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(4096, sr);

				KeyPair kp = kpg.genKeyPair();
				PublicKey publicKey = kp.getPublic();
				PrivateKey privateKey = kp.getPrivate();

				byte[] privBytes = privateKey.getEncoded();
				PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privBytes);
				ASN1Encodable encodable = pkInfo.parsePrivateKey();
				ASN1Primitive primitive = encodable.toASN1Primitive();
				byte[] privateKeyPKCS1 = primitive.getEncoded();
				LOCAL_PRKEY = privateKeyPKCS1;

				byte[] pubBytes = publicKey.getEncoded();
				SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(pubBytes);
				ASN1Primitive primitivep = spkInfo.parsePublicKey();
				byte[] publicKeyPKCS1 = primitivep.getEncoded();
				LOCAL_PBKEY = publicKeyPKCS1;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Return the control's public key value from public key's bytes in RSA hashing.
	 * 
	 * @throws KeyConvertException : throw if ther's an error while trying to
	 *                             convert control's public key.
	 */
	public static PublicKey getControlPublicKey() throws KeyConvertException {
		return null;
	}

	/**
	 * Return the public key value in RSA hashing.
	 * 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static PublicKey getLocalPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		return PKCS18EncodedKeySpec.decodePKCS1PublicKey(LOCAL_PBKEY);
	}

	/**
	 * Return the private key value in PKCS1 RSA hashing.
	 * 
	 * @throws KeyConvertException Error while getting PrivateKey
	 */
	public static PrivateKey getLocalPrivateKey() throws KeyConvertException {
		return PKCS18EncodedKeySpec.readPkcs1PrivateKey(LOCAL_PRKEY);
	}

	/**
	 * Return the public key string from byte[] using Base64 Encoder.
	 * 
	 * @return The public key in string
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static String getPublicKeyString() throws NoSuchAlgorithmException, InvalidKeySpecException {
		return Base64.getEncoder().encodeToString(getLocalPublicKey().getEncoded());
	}

	/**
	 * Return the private key string from byte[] using Base64 Encoder.
	 * 
	 * @return The private key in string
	 * @throws KeyConvertException Error while getting PrivateKey's string
	 */
	public static String getPrivateKeyString() throws KeyConvertException {
		return Base64.getEncoder().encodeToString(getLocalPrivateKey().getEncoded());
	}

	/**
	 * This method will decode the hashed text received from FES's control cloud
	 * using local RSA main key.
	 * 
	 * @param hashedText : The text that has been encrypted
	 * @return The decoded text using local RSA main key
	 */
	public static String getRSADecodingToString(String hashedText) throws DecodeHashException {
		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, getLocalPrivateKey());
			byte decryptOut[] = c.doFinal(Base64.getDecoder().decode(hashedText));
			return new String(decryptOut);
		} catch (Exception ex) {
			ex.printStackTrace();
			return "";
//			throw new DecodeHashException("Cannot decode the data received from FES's control cloud !");
		}
	}

	public static String getRSAEncodingToString(String text) {
		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, getLocalPublicKey());
			byte encryptOut[] = c.doFinal(text.getBytes());
			String strEncrypt = Base64.getEncoder().encodeToString(encryptOut);
			return strEncrypt;
		} catch (Exception ex) {
			ex.printStackTrace();
			return "";
		}
	}

}
