package me.sniggle.pgp.crypt;

import me.sniggle.pgp.crypt.internal.BaseKeyPairGenerator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Created by iulius on 16/09/15.
 */
public class PGPKeyPairGenerator extends BaseKeyPairGenerator {

  public PGPKeyPairGenerator() {
  }

  private PGPKeyRingGenerator createKeyRingGenerator(String id, String password, int keySize) {
    PGPKeyRingGenerator generator = null;
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(KEY_ALGORITHM);
      keyPairGenerator.initialize(keySize, getSecureRandom());
      PGPKeyPair signingKeyPair = new PGPKeyPair(getSigningKeyType(), keyPairGenerator.generateKeyPair(), new Date());
      PGPKeyPair encryptionKeyPair = new PGPKeyPair(getEncryptionKeyType(), keyPairGenerator.generateKeyPair(), new Date());
      PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
      signatureSubpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
      signatureSubpacketGenerator.setPreferredSymmetricAlgorithms(false, getPreferredEncryptionAlgorithms());
      signatureSubpacketGenerator.setPreferredHashAlgorithms(false, getPreferredHashingAlgorithms());
      signatureSubpacketGenerator.setPreferredCompressionAlgorithms(false, getPreferredCompressionAlgorithms());

      PGPSignatureSubpacketGenerator encryptionSubpacketGenerator = new PGPSignatureSubpacketGenerator();
      encryptionSubpacketGenerator.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

      generator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, signingKeyPair, id, getEncryptionAlgorithm(), password.toCharArray(), false, signatureSubpacketGenerator.generate(), null, new SecureRandom(), getProvider());
      generator.addSubKey(encryptionKeyPair, encryptionSubpacketGenerator.generate(), null);
    } catch (NoSuchProviderException | NoSuchAlgorithmException | PGPException e) {
      e.printStackTrace();
      generator = null;
    }
    return generator;
  }

  protected  String getProvider() {
    return "BC";
  }

  @Override
  public boolean generateKeyPair(String id, String password, int keySize, OutputStream publicKey, OutputStream secrectKey) {
    boolean result = true;
    PGPKeyRingGenerator keyRingGenerator = createKeyRingGenerator(id, password, keySize);
    PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();
    PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();
    try( OutputStream targetStream = new ArmoredOutputStream(publicKey) ) {
      publicKeyRing.encode(targetStream);
    } catch (IOException e) {
      result &= false;
    }
    try( OutputStream targetStream = new ArmoredOutputStream(secrectKey) ) {
      secretKeyRing.encode(targetStream);
    } catch (IOException e) {
      e.printStackTrace();
      result &= false;
    }
    return result;
  }

}
