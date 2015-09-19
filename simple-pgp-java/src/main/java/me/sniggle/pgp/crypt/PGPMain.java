package me.sniggle.pgp.crypt;

import org.bouncycastle.bcpg.ArmoredOutputStream;

import java.io.*;

/**
 * Created by iulius on 17/09/15.
 */
public class PGPMain {

  public static void main(String[] args) throws IOException {
    PGPWrapperFactory.init();
    /*KeyPairGenerator generator = PGPWrapperFactory.getKeyPairGenerator();
    try( OutputStream publicKeyStream = new FileOutputStream("simple-pgp-java/src/main/resources/test.asc") ) {
      try( OutputStream privateKeyStream = new FileOutputStream("simple-pgp-java/src/main/resources/test-sec.asc") ) {
        generator.generateKeyPair("iulius@sniggle.me", "testpassword", 4096, publicKeyStream, privateKeyStream);
      }
    }*/

    MessageEncryptor messageEncryptor = PGPWrapperFactory.getEncyptor();
    MessageSigner messageSigner = PGPWrapperFactory.getSigner();
    /*
    try( InputStream publicKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test.asc") ) {
      try( InputStream plainTextStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.txt") ) {
        try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.txt.asc")) {
          System.out.println(messageEncryptor.encrypt(publicKeyStream, "test-message", plainTextStream, out));
        }
      }
    }
    */
    /**
    try( InputStream publicKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/test-pub.asc") ) {
      try( InputStream privateKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-sec.asc") ) {
        try( InputStream plainTextStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.txt") ) {
          try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.txt.bc.asc")) {
            System.out.println(messageEncryptor.encrypt(publicKeyStream, privateKeyStream, "iulius@sniggleme.info", "testpassword", "test-message", plainTextStream, out));
          }
        }
      }
    }
     **/
    /*
    try( InputStream secretKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-sec.asc") ) {
      try( InputStream encryptedTextStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.txt.asc") ) {
        try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.out.txt")) {
          System.out.println(messageEncryptor.decrypt("testpassword", secretKeyStream, encryptedTextStream, out));
        }
      }
    }
    */
    /**
    try( InputStream secretKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/test-sec.asc") ) {
      try( InputStream publicKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-pub.asc") ) {
        try (InputStream encryptedTextStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.txt.bc.asc")) {
          try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/test-message.sign.pub.out.txt")) {
            System.out.println(messageEncryptor.decrypt("testpassword", secretKeyStream, publicKeyStream, encryptedTextStream, out));
          }
        }
      }
    }
    try( InputStream secretKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-sec.asc") ) {
      try( InputStream publicKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/iulius@gutberlet.eu-pub.asc") ) {
        try (InputStream encryptedTextStream = new FileInputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.txt.pgp.asc")) {
          try (OutputStream out = new FileOutputStream("simple-pgp-java/src/main/resources/snigglemeinfo-test-message.sign.pub.out.txt")) {
            System.out.println(messageEncryptor.decrypt("testpassword", secretKeyStream, publicKeyStream, encryptedTextStream, out));
          }
        }
      }
    }
     **/
    /***
    try( OutputStream signatureStream = new FileOutputStream("simple-pgp-java/src/main/resources/test-message.sig") ) {
      try (InputStream messageStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.txt")) {
        try (InputStream privateKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/test-sec.asc")) {
          messageSigner.signMessage(privateKeyStream, "iulius@sniggleme.info", "testpassword", messageStream, new ArmoredOutputStream(signatureStream));
        }
      }
    }
     ***/
    try( InputStream publicKeyStream = new FileInputStream("simple-pgp-java/src/main/resources/iulius@gutberlet.eu-pub.asc") ) {
      try( InputStream messageStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.txt") ) {
        try (InputStream signatureStream = new FileInputStream("simple-pgp-java/src/main/resources/test-message.gpg.sig")) {
          messageSigner.verifyMessage(publicKeyStream, messageStream, signatureStream);
        }
      }
    }
  }

}
