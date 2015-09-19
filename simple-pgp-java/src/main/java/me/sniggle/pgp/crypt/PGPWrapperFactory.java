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

  public static MessageEncryptor getEncyptor() {
    return new PGPMessageEncryptor();
  }

  public static KeyPairGenerator getKeyPairGenerator() {
    return new PGPKeyPairGenerator();
  }

  public static MessageSigner getSigner() {
    return new PGPMessageSigner();
  }

}
