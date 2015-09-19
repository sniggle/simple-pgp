package me.sniggle.pgp.crypt;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 16/09/15.
 */
public interface MessageSigner {

  boolean verifyMessage(InputStream publicKeyOfSender, InputStream message, InputStream signatureStream);

  boolean signMessage(InputStream privateKeyOfSender, String userIdForPrivateKey, String passwordOfPrivateKey, InputStream message, OutputStream signedMessage);

}
