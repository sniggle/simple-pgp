package me.sniggle.pgp.crypt;

import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 16/09/15.
 */
public interface MessageEncryptor {

  boolean encrypt(InputStream publicKeyOfRecipient, String inputDataName, InputStream plainInputData, OutputStream target);

  boolean encrypt(InputStream publicKeyOfRecipient, InputStream privateKeyOfSender, String userIdOfSender, String passwordOfSendersPrivateKey, String inputDataName, InputStream plainInputData, OutputStream target);

  boolean decrypt(String passwordOfReceiversPrivateKey, InputStream privateKeyOfReceiver, InputStream encryptedData, OutputStream target);

  boolean decrypt(String passwordOfReceiversPrivateKey, InputStream privateKeyOfReceiver, InputStream publicKeyOfSender, InputStream encryptedData, OutputStream target);

}
