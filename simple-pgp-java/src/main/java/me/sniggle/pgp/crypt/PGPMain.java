package me.sniggle.pgp.crypt;

import java.io.*;

/**
 * Created by iulius on 17/09/15.
 */
public class PGPMain {

  public static void main(String[] args) throws IOException {
    PGPWrapperFactory.init();
    KeyPairGenerator generator = PGPWrapperFactory.getKeyPairGenerator();
    try( OutputStream publicKeyStream = new FileOutputStream("simple-pgp-java/src/main/resources/test.asc") ) {
      try( OutputStream privateKeyStream = new FileOutputStream("simple-pgp-java/src/main/resources/test-sec.asc") ) {
        generator.generateKeyPair("iulius@sniggle.me", "testpassword", 4096, publicKeyStream, privateKeyStream);
      }
    }
    Encryptor encryptor = PGPWrapperFactory.getEncyptor();
    try( InputStream publicKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/test.asc") ) {
      try( InputStream plainTextStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.txt") ) {
        try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/test-message.txt.asc")) {
          System.out.println(encryptor.encrypt(publicKeyStream, "test-message", plainTextStream, out));
        }
      }
    }
    try( InputStream secretKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/test-sec.asc") ) {
      try( InputStream encryptedTextStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.txt.asc") ) {
        try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/test-message.out.txt")) {
          System.out.println(encryptor.decrypt("testpassword", secretKeyStream, encryptedTextStream, out));
        }
      }
    }
  }

}
