package me.sniggle.pgp.crypt;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

/**
 * Created by iulius on 19/09/15.
 */
@RunWith(Parameterized.class)
public class PGPMessageEncryptorDecryptTest {

  private MessageEncryptor messageEncryptor;
  private String password;
  private String privateKeyFilename;
  private String encryptedDataFilename;
  private String expectedMessage;

  public PGPMessageEncryptorDecryptTest(String password, String privateKeyFilename, String encryptedDataFilename, String expectedMessage) {
    this.password = password;
    this.privateKeyFilename = privateKeyFilename;
    this.encryptedDataFilename = encryptedDataFilename;
    this.expectedMessage = expectedMessage;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList( new Object[][] {
        { "testpassword", "testcase-1-sec.asc", "test-message.txt.tc1.gpg", "Hello World!" },
        { "testpassword", "testcase-2-sec.asc", "test-message.txt.tc2.gpg", "Hello World!" }
    });
  }

  @Before
  public void setup() {
    messageEncryptor = PGPWrapperFactory.getEncyptor();
  }

  @Test
  public void testDecryptWithoutSignage() throws FileNotFoundException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    boolean actualResult = messageEncryptor.decrypt(password, getClass().getResourceAsStream(privateKeyFilename), getClass().getResourceAsStream(encryptedDataFilename), baos);
    assertEquals(expectedMessage != null, actualResult);
    assertEquals(expectedMessage, new String(baos.toByteArray()));
  }

  @After
  public void cleanUp() {
    messageEncryptor = null;
  }

}
