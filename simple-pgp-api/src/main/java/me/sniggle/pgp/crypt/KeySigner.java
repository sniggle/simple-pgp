package me.sniggle.pgp.crypt;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 18/09/15.
 */
public interface KeySigner {

  boolean signKey(InputStream publicKey, InputStream privateKey, OutputStream targetStream);

}
