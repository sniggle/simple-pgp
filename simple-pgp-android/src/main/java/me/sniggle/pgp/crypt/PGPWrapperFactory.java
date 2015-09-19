package me.sniggle.pgp.crypt;

import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * Created by iulius on 16/09/15.
 */
public final class PGPWrapperFactory {

  private PGPWrapperFactory() {
    super();
  }

  public static void init() {
    Security.insertProviderAt(new BouncyCastleProvider(), 0);
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
