package encript;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Base64;

/**
 * This class provides utility methods that can be used for encryption of
 * various data as per the UIDAI Authentication API.
 * 
 * It uses <a href="http://www.bouncycastle.org/">Bouncy Castle APIs</a>.
 * 
 * @author UIDAI
 *
 */
public class AESCipher {

	// AES-GCM parameters

	// AES Key size - in bits
	public static final int AES_KEY_SIZE_BITS = 256;

	// IV length - last 96 bits of ISO format timestamp
	public static final int IV_SIZE_BITS = 96;

	// Additional authentication data - last 128 bits of ISO format timestamp
	public static final int AAD_SIZE_BITS = 128;

	// Authentication tag length - in bits
	public static final int AUTH_TAG_SIZE_BITS = 128;

	private static final String JCE_PROVIDER = "BC";

	/**
	 * Hashing Algorithm Used for encryption and decryption
	 */
	private String algorithm = "SHA-256";

	/**
	 * SHA-256 Implementation provider
	 */
	private final static String SECURITY_PROVIDER = "BC";

	/**
	 * Default Size of the HMAC/Hash Value in bytes
	 */
	private int HMAC_SIZE = 32;
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static final String CERTIFICATE_TYPE = "X.509";
	private PublicKey publicKey;
	private Date certExpiryDate;
	
	public AESCipher(String publicKeyFileName) {
		FileInputStream fileInputStream = null;
		try {
			CertificateFactory certFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE, SECURITY_PROVIDER);
			fileInputStream = new FileInputStream(new File(publicKeyFileName));
			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fileInputStream);
			publicKey = cert.getPublicKey();
			certExpiryDate = cert.getNotAfter();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Could not intialize encryption module", e);
		} finally {
			if (fileInputStream != null) {
				try {
					fileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Encrypts given data using session key, iv, aad
	 * 
	 * @param cipherOperation - true for encrypt, false otherwise
	 * @param skey            - Session key
	 * @param iv              - initialization vector or nonce
	 * @param aad             - additional authenticated data
	 * @param data            - data to encrypt
	 * @return encrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 */
	private byte[] encryptDecryptUsingSessionKey(boolean cipherOperation, byte[] skey, byte[] iv, byte[] aad,
			byte[] data) throws IllegalStateException, InvalidCipherTextException {

		AEADParameters aeadParam = new AEADParameters(new KeyParameter(skey), AUTH_TAG_SIZE_BITS, iv, aad);
		GCMBlockCipher gcmb = new GCMBlockCipher(new AESEngine());

		gcmb.init(cipherOperation, aeadParam);
		int outputSize = gcmb.getOutputSize(data.length);
		byte[] result = new byte[outputSize];
		int processLen = gcmb.processBytes(data, 0, data.length, result, 0);
		gcmb.doFinal(result, processLen);
		return result;
	}

	/**
	 * Creates a AES key that can be used as session key (skey)
	 * 
	 * @return session key byte array
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	private byte[] generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES", JCE_PROVIDER);
		kgen.init(AES_KEY_SIZE_BITS);
		SecretKey key = kgen.generateKey();
		byte[] symmKey = key.getEncoded();
		return symmKey;
	}

	/**
	 * Get current ISO time
	 * 
	 * @return current time in String
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	private String getCurrentISOTimeInUTF8() {
		SimpleDateFormat df = new SimpleDateFormat("YYYY-MM-DD'T'hh:mm:ss");
		String timeNow = df.format(new Date());
		return timeNow;
	}

	/**
	 * Generate IV using timestamp
	 * 
	 * @param ts - timestamp string
	 * @return 12 bytes array
	 * @throws UnsupportedEncodingException
	 */
	private byte[] generateIv(String ts) throws UnsupportedEncodingException {
		return getLastBits(ts, IV_SIZE_BITS / 8);
	}

	/**
	 * Generate AAD using timestamp
	 * 
	 * @param ts - timestamp string
	 * @return 16 bytes array
	 * @throws UnsupportedEncodingException
	 */
	private byte[] generateAad(String ts) throws UnsupportedEncodingException {
		return getLastBits(ts, AAD_SIZE_BITS / 8);
	}

	/**
	 * Fetch specified last bits from String
	 * 
	 * @param ts   - timestamp string
	 * @param bits - no of bits to fetch
	 * @return byte array of specified length
	 * @throws UnsupportedEncodingException
	 */
	private byte[] getLastBits(String ts, int bits) throws UnsupportedEncodingException {
		byte[] tsInBytes = ts.getBytes("UTF-8");
		return Arrays.copyOfRange(tsInBytes, tsInBytes.length - bits, tsInBytes.length);
	}

	/**
	 * Main method
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		AESCipher aesCipher = new AESCipher("C:\\Users\\kapko\\OneDrive\\Documents\\Project\\Spring_Security\\TestExample\\src\\encript\\uidai_auth_prod.cer");
		byte[] inputData = "UIDAI World!".getBytes();
		
		Timestamp timestamp = new Timestamp(System.currentTimeMillis());
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		String date = sdf.format(timestamp);
		String mobileOTP = "141537";
		String pid = "<Pid ts=\"" + date + "\" ver=\"2.0\" wadh=\"\"> <Pv otp=\"" + mobileOTP + "\" />" + "</Pid>"; 

//        String pid = "<Pid ts=\"" + date + "\" ver=\"2.0\" wadh=””>\r\n"
//        		+ " <Demo lang=\"\">\r\n"
//        		+ " <Pi ms=\"\" mv=\"\" name=\"\" lname=\"\" lmv=\"\" gender=\"\" dob=\"\"\r\n"
//        		+ "dobt=\"\" age=\"\" phone=\"\" email=\"\"/>\r\n"
//        		+ " <Pa ms=\"\" co=\"\" house=\"\" street=\"\" lm=\"\" loc=\"\"\r\n"
//        		+ " vtc=\"\" subdist=\"\" dist=\"\" state=\"\" country=\"\" pc=\"\" po=\"\"/>\r\n"
//        		+ " <Pfa ms=\"\" mv=\"\" av=\"\" lav=\"\" lmv=\"\"/>\r\n"
//        		+ " </Demo>\r\n"
//        		+ " <Pv otp=\"822076\" pin=\"\"/>\r\n"
//        		+ "</Pid>";
		
		
		byte[] sessionKey = aesCipher.generateSessionKey();

		String ts = aesCipher.getCurrentISOTimeInUTF8();

		System.out.println("Plain text Hex  ---> " + byteArrayToHexString(pid.getBytes()));

		byte[] cipherTextWithTS = aesCipher.encrypt(pid.getBytes(), sessionKey, ts);
		System.out.println("Cipher text Hex ---> " + byteArrayToHexString(cipherTextWithTS));

//        ---------------------------------------------------------

		byte[] srcHash = aesCipher.generateHash(pid.getBytes());
		System.out.println("source Hash in Hex ---> " + byteArrayToHexString(srcHash));
		byte[] iv = aesCipher.generateIv(ts);
		byte[] aad = aesCipher.generateAad(ts);
		byte[] encSrcHash = aesCipher.encryptDecryptUsingSessionKey(true, sessionKey, iv, aad, srcHash);
		System.out.println("encrypted Hash Cipher text Hex ---> " + byteArrayToHexString(encSrcHash));

		byte[] decryptedText = aesCipher.decrypt(cipherTextWithTS, sessionKey, encSrcHash);
		System.out.println("Decrypted Plain text Hex  ---> " + byteArrayToHexString(decryptedText));
		
		byte[] encryptedSessionKey =  aesCipher.encryptUsingPublicKey(sessionKey);
		String encryptBase64 = Base64.getEncoder().encodeToString(encryptedSessionKey);
		
		
		System.out.println("-------------------final encrypted data------------------");
		System.out.println("PID= "+Base64.getEncoder().encodeToString(cipherTextWithTS));
		System.out.println("encrypted SRC Hash= "+ Base64.getEncoder().encodeToString(encSrcHash));
		System.out.println("encryptedSessionKey= "+encryptBase64);
		System.out.println("date= "+ date);
	}

	/**
	 * Convert byte array to hex string
	 * 
	 * @param bytes - input bytes
	 * @return - hex string
	 */
	private static String byteArrayToHexString(byte[] bytes) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			result.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
		}
		return result.toString();
	}

	/**
	 * Convert hex string to byte array
	 * 
	 * @param data - input hex string
	 * @return byte array
	 */
	private static byte[] hexStringToByteArray(String data) {
		int k = 0;
		byte[] results = new byte[data.length() / 2];
		for (int i = 0; i < data.length();) {
			results[k] = (byte) (Character.digit(data.charAt(i++), 16) << 4);
			results[k] += (byte) (Character.digit(data.charAt(i++), 16));
			k++;
		}
		return results;
	}

	/**
	 * Encrypts given data using a generated session and used ts as for all other
	 * needs.
	 * 
	 * @param inputData  - data to encrypt
	 * @param sessionKey - Session key
	 * @param ts         - timestamp as per the PID
	 * @return encrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws Exception
	 */
	public byte[] encrypt(byte[] inputData, byte[] sessionKey, String ts)
			throws IllegalStateException, InvalidCipherTextException, Exception {
		byte[] iv = this.generateIv(ts);
		byte[] aad = this.generateAad(ts);
		byte[] cipherText = this.encryptDecryptUsingSessionKey(true, sessionKey, iv, aad, inputData);
		byte[] tsInBytes = ts.getBytes("UTF-8");
		byte[] packedCipherData = new byte[cipherText.length + tsInBytes.length];
		System.arraycopy(tsInBytes, 0, packedCipherData, 0, tsInBytes.length);
		System.arraycopy(cipherText, 0, packedCipherData, tsInBytes.length, cipherText.length);
		return packedCipherData;
	}

	/**
	 * Decrypts given input data using a sessionKey.
	 * 
	 * @param inputData  - data to decrypt
	 * @param sessionKey - Session key
	 * @return decrypted data
	 * @throws IllegalStateException
	 * @throws InvalidCipherTextException
	 * @throws Exception
	 */
	public byte[] decrypt(byte[] inputData, byte[] sessionKey, byte[] encSrcHash)
			throws IllegalStateException, InvalidCipherTextException, Exception {
		byte[] bytesTs = Arrays.copyOfRange(inputData, 0, 19);
		String ts = new String(bytesTs);
		byte[] cipherData = Arrays.copyOfRange(inputData, bytesTs.length, inputData.length);
		byte[] iv = this.generateIv(ts);
		byte[] aad = this.generateAad(ts);
		byte[] plainText = this.encryptDecryptUsingSessionKey(false, sessionKey, iv, aad, cipherData);
		byte[] srcHash = this.encryptDecryptUsingSessionKey(false, sessionKey, iv, aad, encSrcHash);
		System.out.println("Decrypted HAsh in cipher text: " + byteArrayToHexString(srcHash));
		boolean result = this.validateHash(srcHash, plainText);
		if (!result) {
			throw new Exception("Integrity Validation Failed : "
					+ "The original data at client side and the decrypted data at server side is not identical");
		} else {
			System.out.println("Hash Validation is Successful!!!!!");
			return plainText;
		}
	}

//	------------------------------------------------------------------------------------------------------------------------------------------------------------------

	/**
	 * Returns true / false value based on Hash comparison between source and
	 * generated
	 * 
	 * @param srcHash
	 * @param plainTextWithTS
	 * @return hash value
	 * @throws Exception
	 */
	private boolean validateHash(byte[] srcHash, byte[] plainTextWithTS) throws Exception {
		byte[] actualHash = this.generateHash(plainTextWithTS);
		System.out.println("Hash of actual plain text in cipher hex:--->" + byteArrayToHexString(actualHash));
//		boolean tr =  Arrays.equals(srcHash, actualHash);
		if (new String(srcHash, "UTF-8").equals(new String(actualHash, "UTF-8"))) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Returns the 256 bit hash value of the message
	 * 
	 * @param message full plain text
	 * 
	 * @return hash value
	 * @throws HashingException
	 * @throws HashingException I/O errors
	 */
	public byte[] generateHash(byte[] message) throws Exception {
		byte[] hash = null;
		try {
			MessageDigest digest = MessageDigest.getInstance(algorithm, SECURITY_PROVIDER);
			digest.reset();
			HMAC_SIZE = digest.getDigestLength();
			hash = digest.digest(message);
		} catch (GeneralSecurityException e) {
			throw new Exception("SHA-256 Hashing algorithm not available");
		}
		return hash;
	}
	
	public byte[] encryptUsingPublicKey(byte[] data) throws IOException, GeneralSecurityException {
		Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		pkCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encSessionKey = pkCipher.doFinal(data);
		return encSessionKey;
	}

}
