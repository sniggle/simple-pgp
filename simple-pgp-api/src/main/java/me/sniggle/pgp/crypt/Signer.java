package me.sniggle.pgp.crypt;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 16/09/15.
 */
public interface Signer {

  boolean verifyMessage(InputStream publicKey, InputStream message);

  boolean signMessage(InputStream privateKey, InputStream message, OutputStream signedMessage);

}
