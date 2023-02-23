package test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class Encrypt2 {

	private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	private static final String SECURITY_PROVIDER = "BC";
	private static final String CERTIFICATE_TYPE = "X.509";
	private PublicKey publicKey;
	private Date certExpiryDate;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public Encrypt2(String publicKeyFileName) {
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

	public static void main(String[] args) throws IOException, GeneralSecurityException, InvalidCipherTextException {

		Encrypt2 encryp = new Encrypt2(CERTIFICATE_TYPE);

		Timestamp timestamp = new Timestamp(System.currentTimeMillis());
		String date = sdf.format(timestamp);

		String pid = "<Pid ts=\"2023-02-05T21:32:34\" ver=\"2.0\" wadh=\"\"> <Pv otp=\"220229\" /></Pid>";

		byte[] pidBytes = pid.getBytes();
		byte[] skeydata = generateSessionKey();
		byte[] encryptedSessionKey = encryp.encryptUsingPublicKey(skeydata);
		byte[] encryptedPid = encryp.encryptUsingSessionKey(skeydata, pidBytes, date.getBytes());
		byte[] hmac = encryp.getSHA256Hash(pidBytes);

		byte[] encryptedHmacBytes = encryp.encryptUsingSessionKey(skeydata, hmac, date.getBytes());
		
		byte[] bio = new byte[date.getBytes().length + encryptedPid.length];
		System.arraycopy(date.getBytes(), 0, bio, 0, date.getBytes().length);
		System.arraycopy(encryptedPid, 0, bio, date.getBytes().length, encryptedPid.length);
		
		String encryptedPidInBase64 = new String(Base64.encode(bio));
		String encryptedHmacInBase64 = new String(Base64.encode(encryptedHmacBytes));
		String sessionKey = new String(Base64.encode(encryptedSessionKey));


	}

	public static long get6DigitRandomNumber() {
		Random rnd = new Random();
		long number = rnd.nextLong(); // 999999
		return number;
	}

	public static long get16DigitRandomNumber() {
		Random rand = new Random();
		long x = (long) (rand.nextDouble() * 100000000000000L);
		String s = String.valueOf(21) + String.format("%014d", x);
		return Long.valueOf(s);
	}

	public static byte[] generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(256);
		SecretKey symmetricKey = kgen.generateKey();
		return symmetricKey.getEncoded();
	}

	public String getCertExpiryDate() {
		SimpleDateFormat ciDateFormat = new SimpleDateFormat("yyyyMMdd");
		ciDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		String certificateIdentifier = ciDateFormat.format(this.certExpiryDate);
		return certificateIdentifier;
	}

	public byte[] encryptUsingPublicKey(byte[] data) throws IOException, GeneralSecurityException {
		Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
		pkCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encSessionKey = pkCipher.doFinal(data);
		return encSessionKey;
	}

	public byte[] encryptUsingSessionKey(byte[] skey, byte[] data, byte[] ts) throws InvalidCipherTextException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {

		// Last 12-bytes of ts as IV or Nonce
		byte[] iv = new byte[12];
		System.arraycopy(ts, ts.length - 12, iv, 0, iv.length);

		// Last 16-bytes of ts as AAD
		byte[] aad = new byte[16];
		System.arraycopy(ts, ts.length - 16, aad, 0, aad.length);

		// Authenticated Encryption with Associated Data (AEAD)
		AEADParameters parameters = new AEADParameters(new KeyParameter(skey), 128, iv, aad);

		GCMBlockCipher gcmEngine = new GCMBlockCipher(new AESEngine());
		gcmEngine.init(true, parameters);
		byte[] encMsg = new byte[gcmEngine.getOutputSize(data.length)];
		int encLen = gcmEngine.processBytes(data, 0, data.length, encMsg, 0);
		encLen += gcmEngine.doFinal(encMsg, encLen);
		return encMsg;
	}

	public byte[] getSHA256Hash(byte[] data) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(data);
			return hash;
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

}
