package me.sniggle.pgp.crypt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Created by iulius on 16/09/15.
 */
public final class PGPWrapperFactory {

  private PGPWrapperFactory() {
    super();
  }

  public static void init() {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static Encryptor getEncyptor() {
    return new PGPEncryptor();
  }

  public static KeyPairGenerator getKeyPairGenerator() {
    return new PGPKeyPairGenerator();
  }

  public static Signer getSigner() {
    return null;
  }

}
