package me.sniggle.pgp.crypt;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.*;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by iulius on 19/09/15.
 */
@RunWith(Parameterized.class)
public class PGPMessageEncryptorEncryptTest {

  private MessageEncryptor messageEncryptor;
  private final String privateKeyFilename;
  private final String publicKeyFilename;
  private final String plainDataFilename;
  private final String userId;

  public PGPMessageEncryptorEncryptTest(String publicKeyFilename, String privateKeyFilename, String userId, String plainDataFilename) {
    this.publicKeyFilename = publicKeyFilename;
    this.plainDataFilename = plainDataFilename;
    this.privateKeyFilename = privateKeyFilename;
    this.userId = userId;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList( new Object[][] {
        { "testcase-1-pub.asc", "testcase-1-sec.asc", "testcase-1@sniggleme.info", "test-message.txt" },
        { "testcase-2-pub.asc", "testcase-2-sec.asc", "testcase-2@sniggleme.info", "test-message.txt" }
    });
  }

  @Before
  public void setUp() throws Exception {
    messageEncryptor = PGPWrapperFactory.getEncyptor();
  }

  @Test
  public void testEncrypt() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    assertTrue(messageEncryptor.encrypt( getClass().getResourceAsStream(publicKeyFilename), "test-message.txt", getClass().getResourceAsStream(plainDataFilename), baos));
    ByteArrayOutputStream plainResult = new ByteArrayOutputStream();
    assertTrue(messageEncryptor.decrypt("testpassword", getClass().getResourceAsStream(privateKeyFilename), new ByteArrayInputStream(baos.toByteArray()), plainResult));
    assertEquals("Hello World!", new String(plainResult.toByteArray()));
  }

  @Test
  public void testEncryptAndSign() throws FileNotFoundException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    assertTrue(messageEncryptor.encrypt(
        getClass().getResourceAsStream(publicKeyFilename),
        getClass().getResourceAsStream(privateKeyFilename),
        userId,
        "testpassword",
        "test-message.txt",
        getClass().getResourceAsStream(plainDataFilename),
        baos
    ));
    ByteArrayOutputStream plainText = new ByteArrayOutputStream();
    assertTrue(messageEncryptor.decrypt(
        "testpassword",
        getClass().getResourceAsStream(privateKeyFilename),
        getClass().getResourceAsStream(publicKeyFilename),
        new ByteArrayInputStream(baos.toByteArray()),
        plainText
    ));
    assertEquals("Hello World!", new String(plainText.toByteArray()));
  }

  @After
  public void tearDown() throws Exception {
    messageEncryptor = null;
  }
}
