package me.sniggle.pgp.crypt;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 18/09/15.
 */
public class PGPSigner implements Signer {

  @Override
  public boolean verifyMessage(InputStream publicKey, InputStream message) {
    return false;
  }

  @Override
  public boolean signMessage(InputStream privateKey, InputStream message, OutputStream signedMessage) {
    return false;
  }

}
