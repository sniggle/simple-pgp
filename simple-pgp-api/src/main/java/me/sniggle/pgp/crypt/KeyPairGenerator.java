package me.sniggle.pgp.crypt;

import java.io.OutputStream;

/**
 * Created by iulius on 16/09/15.
 */
public interface KeyPairGenerator {

  String KEY_ALGORITHM = "RSA";
  int DEFAULT_KEY_SIZE = 4096;

  boolean generateKeyPair(String id, String password, OutputStream publicKey, OutputStream secrectKey);

  boolean generateKeyPair(String id, String password, int keySize, OutputStream publicKey, OutputStream secrectKey);

}
