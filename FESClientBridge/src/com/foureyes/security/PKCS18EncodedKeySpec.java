package com.foureyes.security;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bukkit.Bukkit;

import com.foureyes.exception.KeyConvertException;
import com.foureyes.utilities.BroadcastPane;

/**
 * This class will help us to generate 2 special type of RSA-encrypting sessions
 * : PKCS1 and PKCS8 PKCS1 cannot be created directly, it must be converted from
 * PKCS8 PKCS1 & PKCS8 is very good at data-transfering security because we are
 * using an 4096-bit hash-code, so they are perfect enough to encrypt data.
 * Although we are able to use X509EncodedKeySpec, but there would be some
 * conflicts between this plugin and FES's cloud. That's another reason that we
 * decided to use PKCS1/8
 */
public class PKCS18EncodedKeySpec {

	/**
	 * This method will convert PKCS8 from PKCS8 byte[] by using SunRSASign.
	 * 
	 * @param pkcs8Bytes : The PKCS8 byte[] that need converting to PrivateKey
	 * @return The converted PKCS8 PrivateKey
	 * @throws KeyConvertException : Which will throw when getting an error while
	 *                             converting
	 */
	public static PrivateKey readPkcs8PrivateKey(byte[] pkcs8Bytes) throws KeyConvertException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
			return keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			BroadcastPane.showErrorAndContact(Bukkit.getPluginManager().getPlugin("FESClientBridge"),
					"Chúng tôi không thể tạo mã hóa !\n" + "Đây là lỗi liên quan đến hệ thống, vui lòng liên hệ"
							+ "\nvới chúng tôi để được sửa chữa !");
			throw new KeyConvertException("Cannot convert PKCS8 main key !");
		}
	}

	/**
	 * This method will convert PKCS1 from PKCS1 byte[], which is already created in
	 * class <b>X509EncodedKeySpec</b> We can't use Java Internal APIs to parse
	 * ASN.1 structures, so we build a PKCS8 key, which Java can understand.
	 * 
	 * @param pkcs1Bytes : The PKCS1 byte[] that need converting to PrivateKey
	 * @return The converted PKCS1 PrivateKey
	 * @throws KeyConvertException : Which will throw when getting an error while
	 *                             converting
	 */
	public static PrivateKey readPkcs1PrivateKey(byte[] pkcs1Bytes) throws KeyConvertException {
		try {
			int pkcs1Length = pkcs1Bytes.length;
			int totalLength = pkcs1Length + 22;
			byte[] pkcs8Header = new byte[] { 0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff),
					(byte) (totalLength & 0xff), 0x2, 0x1, 0x0, 0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48,
					(byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1, 0x5, 0x0, 0x4, (byte) 0x82,
					(byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) };
			byte[] pkcs8bytes = join(pkcs8Header, pkcs1Bytes);
			return readPkcs8PrivateKey(pkcs8bytes);
		} catch (Exception e) {
			BroadcastPane.showErrorAndContact(Bukkit.getPluginManager().getPlugin("FESClientBridge"),
					"Chúng tôi không thể tạo mã hóa !\n" + "Đây là lỗi liên quan đến hệ thống, vui lòng liên hệ"
							+ "\nvới chúng tôi để được sửa chữa !");
			throw new KeyConvertException("Cannot convert PKCS1 main key !");
		}
	}

	/**
	 * Just a small util method to combine 2 byte-arrays.
	 * 
	 * @param byteArray1 : The first byte[]
	 * @param byteArray2 : The second byte[]
	 * @return The combined array.
	 */
	private static byte[] join(byte[] byteArray1, byte[] byteArray2) {
		byte[] bytes = new byte[byteArray1.length + byteArray2.length];
		System.arraycopy(byteArray1, 0, bytes, 0, byteArray1.length);
		System.arraycopy(byteArray2, 0, bytes, byteArray1.length, byteArray2.length);
		return bytes;
	}

	private static final int SEQUENCE_TAG = 0x30;
	private static final int BIT_STRING_TAG = 0x03;
	private static final byte[] NO_UNUSED_BITS = new byte[] { 0x00 };
	private static final byte[] RSA_ALGORITHM_IDENTIFIER_SEQUENCE = { (byte) 0x30, (byte) 0x0d, (byte) 0x06,
			(byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01,
			(byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00 };

	public static RSAPublicKey decodePKCS1PublicKey(byte[] pkcs1PublicKeyEncoding)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] subjectPublicKeyInfo2 = createSubjectPublicKeyInfoEncoding(pkcs1PublicKeyEncoding);
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey generatePublic = (RSAPublicKey) rsaKeyFactory
				.generatePublic(new java.security.spec.X509EncodedKeySpec(subjectPublicKeyInfo2));
		return generatePublic;
	}

	public static byte[] createSubjectPublicKeyInfoEncoding(byte[] pkcs1PublicKeyEncoding) {
		byte[] subjectPublicKeyBitString = createDEREncoding(BIT_STRING_TAG,
				concat(NO_UNUSED_BITS, pkcs1PublicKeyEncoding));
		byte[] subjectPublicKeyInfoValue = concat(RSA_ALGORITHM_IDENTIFIER_SEQUENCE, subjectPublicKeyBitString);
		byte[] subjectPublicKeyInfoSequence = createDEREncoding(SEQUENCE_TAG, subjectPublicKeyInfoValue);

		return subjectPublicKeyInfoSequence;
	}

	private static byte[] concat(byte[]... bas) {
		int len = 0;
		for (int i = 0; i < bas.length; i++) {
			len += bas[i].length;
		}

		byte[] buf = new byte[len];
		int off = 0;
		for (int i = 0; i < bas.length; i++) {
			System.arraycopy(bas[i], 0, buf, off, bas[i].length);
			off += bas[i].length;
		}

		return buf;
	}

	private static byte[] createDEREncoding(int tag, byte[] value) {
		if (tag < 0 || tag >= 0xFF) {
			throw new IllegalArgumentException("Currently only single byte tags supported");
		}

		byte[] lengthEncoding = createDERLengthEncoding(value.length);

		int size = 1 + lengthEncoding.length + value.length;
		byte[] derEncodingBuf = new byte[size];

		int off = 0;
		derEncodingBuf[off++] = (byte) tag;
		System.arraycopy(lengthEncoding, 0, derEncodingBuf, off, lengthEncoding.length);
		off += lengthEncoding.length;
		System.arraycopy(value, 0, derEncodingBuf, off, value.length);

		return derEncodingBuf;
	}

	private static byte[] createDERLengthEncoding(int size) {
		if (size <= 0x7F) {
			// single byte length encoding
			return new byte[] { (byte) size };
		} else if (size <= 0xFF) {
			// double byte length encoding
			return new byte[] { (byte) 0x81, (byte) size };
		} else if (size <= 0xFFFF) {
			// triple byte length encoding
			return new byte[] { (byte) 0x82, (byte) (size >> Byte.SIZE), (byte) size };
		}

		throw new IllegalArgumentException("size too large, only up to 64KiB length encoding supported: " + size);
	}

}
