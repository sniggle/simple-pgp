package me.sniggle.pgp.crypt.internal;

import me.sniggle.pgp.crypt.KeyPairGenerator;

import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Created by iulius on 17/09/15.
 */
public abstract class BaseKeyPairGenerator implements KeyPairGenerator {

  private boolean unlimitedStrengthEncryption = false;

  protected BaseKeyPairGenerator() {
    super();
  }

  protected SecureRandom getSecureRandom() {
    return new SecureRandom();
  }

  protected int getSigningKeyType() {
    return AlgorithmSelection.getSigningKeyType();
  }

  protected int getEncryptionKeyType() {
    return AlgorithmSelection.getEncryptionKeyType();
  }

  protected int[] getPreferredEncryptionAlgorithms() {
    return AlgorithmSelection.getPreferredEncryptionAlgorithms();
  }

  protected int[] getPreferredHashingAlgorithms() {
    return AlgorithmSelection.getPreferredHashingAlgorithms();
  }

  protected int[] getPreferredCompressionAlgorithms() {
    return AlgorithmSelection.getPreferredCompressionAlgorithms();
  }

  protected abstract String getProvider();

  protected int getEncryptionAlgorithm() {
    return (unlimitedStrengthEncryption) ? AlgorithmSelection.getStrongEncryptionAlgorithm() : AlgorithmSelection.getWeakEncryptionAlgorithm();
  }

  public void setUnlimitedStrengthEncryption(boolean unlimitedStrengthEncryption) {
    this.unlimitedStrengthEncryption = unlimitedStrengthEncryption;
  }

  public boolean generateKeyPair(String id, String password, OutputStream publicKey, OutputStream secrectKey) {
    return generateKeyPair(id, password, DEFAULT_KEY_SIZE, publicKey, secrectKey);
  }

}
