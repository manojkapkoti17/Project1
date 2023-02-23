package test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class Encrypt {

	public static void main(String[] args) throws InvalidKeyException, InvalidCipherTextException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Date date = new Date();
		System.out.println("Date=" + date);

		String dateStr = date.toString();
		byte[] dataDateByte = dateStr.getBytes();

		System.out.println("Byte date=" + dataDateByte);
		
		String data = "<Pid ts=\"2023-02-05T21:32:34\" ver=\"2.0\" wadh=\"\"> <Pv otp=\"220229\" /></Pid>";
		byte[] dataByte = data.getBytes();
		
		String d = "9yi4+H+AOlSLTfDEP9BctbLnFdJ48kpeFyWnRopJE6Y=";//hmac
		byte[] dataByte2 = d.getBytes();
		Encrypt enc = new Encrypt();
//		byte[] encOutput = enc.encryptUsingSessionKey(dataByte2, dataByte, dataDateByte);
		
//		System.out.println(encOutput.toString());
		
		
		
		System.out.println("-------------------------------------------");
		final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

		Timestamp timestamp = new Timestamp(System.currentTimeMillis());

		String date11 = sdf.format(timestamp);
		System.out.println("Date= "+date11);

	}

	public byte[] encryptUsingSessionKey(byte[] skey, byte

	// Last 16-bytes of ts as AAD

	[] data, byte[] ts) throws InvalidCipherTextException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException

	{

		// Last 12-bytes of ts as IV or Nonce

		byte[] iv = new byte[12];

		System.arraycopy(ts, ts.length - 12, iv, 0, iv.length);

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
}
