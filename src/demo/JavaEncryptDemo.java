package test;

import org.apache.commons.codec.binary.Base64;
import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EncryptDemo {

    private static final String CHARSET = "UTF-8";

    private static final String RSA_ALGORITHM = "RSA";

    private static final int KEY_SIZE = 1024;

    public static class KeyStore{
        public String publicKey;
        public String privateKey;
    }

    public static KeyStore createKeys() throws RsaException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            KeyStore keyStore = new KeyStore();
            keyStore.publicKey = new String(Base64.encodeBase64(publicKey.getEncoded()), CHARSET);
            keyStore.privateKey = new String(Base64.encodeBase64(privateKey.getEncoded()), CHARSET);
            return keyStore;
        } catch (Exception e) {
            throw new RsaException(e.getMessage());
        }
    }


    public static String encryptByPrivateKey(String data,String key) throws RsaException {
        try {
            PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(Base64.decodeBase64(key.getBytes(CHARSET)));
            KeyFactory keyFactory= KeyFactory.getInstance(RSA_ALGORITHM);
            PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
            Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return new String(Base64.encodeBase64(cipher.doFinal(data.getBytes(CHARSET))), CHARSET);
        } catch (Exception e) {
            throw new RsaException(e.getMessage());
        }
    }

    public static class RsaException extends Throwable {
        RsaException(String msg) {
            super(msg);
        }
    }

    public static void main(String[] args) {
        String cid = "QmaHem85EydBairSuLSHcSKriu2ZM8qnGUAZSuvEUto1NY";
        try {
            KeyStore keyStore = createKeys();
            String ciphertext = encryptByPrivateKey(cid, keyStore.privateKey);
            System.out.println(String.format("Cid: %s \nCiphertext: %s \n", cid, ciphertext));
        } catch (RsaException e) {
            e.printStackTrace();
        }
    }
}