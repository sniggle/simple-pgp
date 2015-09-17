package me.sniggle.pgp.crypt;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 16/09/15.
 */
public interface Encryptor {

  boolean encrypt(InputStream publicKey, String inputDataName, InputStream inputData, OutputStream target);

  boolean decrypt(String password, InputStream privateKey, InputStream encryptedData, OutputStream plainText);

}
