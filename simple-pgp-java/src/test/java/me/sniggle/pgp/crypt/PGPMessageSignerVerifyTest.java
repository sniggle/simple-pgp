package me.sniggle.pgp.crypt;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

/**
 * Created by iulius on 19/09/15.
 */
@RunWith(Parameterized.class)
public class PGPMessageSignerVerifyTest {

  private final boolean expectedResult;
  private MessageSigner messageSigner;

  private String publicKeyFilename;
  private String plainMessageFilename;
  private String signatureFilename;

  public PGPMessageSignerVerifyTest(String publicKeyFilename, String plainMessageFilename, String signatureFilename, boolean expectedResult) {
    this.publicKeyFilename = publicKeyFilename;
    this.plainMessageFilename = plainMessageFilename;
    this.signatureFilename = signatureFilename;
    this.expectedResult = expectedResult;
  }

  @Parameterized.Parameters
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        {"testcase-1-pub.asc", "test-message.txt", "test-message.txt.tc1.sig", true},
        {"testcase-2-pub.asc", "test-message.txt", "test-message.txt.tc2.sig", true},
        {"testcase-1-pub.asc", "test-message.txt", "test-message.txt.tc2.sig", false},
        {"testcase-2-pub.asc", "test-message.txt", "test-message.txt.tc1.sig", false}
    });
  }

  @Before
  public void setup() {
    messageSigner = PGPWrapperFactory.getSigner();
  }

  @Test
  public void testVerifyMessage() throws FileNotFoundException {
    assertEquals(expectedResult, messageSigner.verifyMessage(getClass().getResourceAsStream(publicKeyFilename), getClass().getResourceAsStream(plainMessageFilename), getClass().getResourceAsStream(signatureFilename)));
  }

  @After
  public void cleanUp() {
    messageSigner = null;
  }

}
