package me.sniggle.pgp.crypt;

import me.sniggle.pgp.crypt.internal.BasePGPCommon;
import me.sniggle.pgp.crypt.internal.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

/**
 * The the library dependent implementation of a MessageSigner
 *
 * @author iulius
 */
public class PGPMessageSigner extends BasePGPCommon implements MessageSigner {

  /**
   * @see MessageSigner#verifyMessage(InputStream, InputStream, InputStream)
   *
   * @param publicKeyOfSender
   *    the public key of the sender of the message
   * @param message
   *    the message / data to verify
   * @param signatureStream
   *    the (detached) signature
   * @return
   */
  @Override
  public boolean verifyMessage(InputStream publicKeyOfSender, InputStream message, InputStream signatureStream) {
    boolean result = false;
    try( InputStream armordPublicKeyStream = new ArmoredInputStream(signatureStream) ) {
      Object pgpObject;
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(armordPublicKeyStream, new BcKeyFingerprintCalculator());
      while( (pgpObject = pgpObjectFactory.nextObject()) != null ) {
        if( pgpObject instanceof PGPSignatureList ) {
          PGPSignatureList signatureList = (PGPSignatureList)pgpObject;
          Iterator<PGPSignature> signatureIterator = signatureList.iterator();
          while( signatureIterator.hasNext() ) {
            final PGPSignature signature = signatureIterator.next();
            PGPPublicKey pgpPublicKey = findPublicKey(publicKeyOfSender, new KeyFilter<PGPPublicKey>() {
              @Override
              public boolean accept(PGPPublicKey pgpKey) {
                return pgpKey.getKeyID() == signature.getKeyID();
              }
            });
            if( pgpPublicKey != null ) {
              signature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
              IOUtils.process(message, new IOUtils.StreamHandler() {
                @Override
                public void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException {
                  signature.update(buffer, offset, length);
                }
              });
              result = signature.verify();
            }
          }
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
    } catch (PGPException e) {
      e.printStackTrace();
    }
    return result;
  }

  /**
   * @see MessageSigner#signMessage(InputStream, String, String, InputStream, OutputStream)
   *
   * @param privateKeyOfSender
   *    the private key of the sender
   * @param userIdForPrivateKey
   *    the user id of the sender
   * @param passwordOfPrivateKey
   *    the password for the private key
   * @param message
   *    the message / data to verify
   * @param signature
   *    the (detached) signature
   * @return
   */
  @Override
  public boolean signMessage(InputStream privateKeyOfSender, final String userIdForPrivateKey, String passwordOfPrivateKey, InputStream message, OutputStream signature) {
    boolean result = false;
    try {
      PGPPrivateKey privateKey = findPrivateKey(privateKeyOfSender, passwordOfPrivateKey,  new KeyFilter<PGPSecretKey>() {

        @Override
        public boolean accept(PGPSecretKey secretKey) {
          boolean result = secretKey.isSigningKey();
          if( result ) {
            Iterator<String> userIdIterator = secretKey.getUserIDs();
            boolean containsUserId = false;
            while( userIdIterator.hasNext() && !containsUserId ) {
              containsUserId |= userIdForPrivateKey.equals(userIdIterator.next());
            }
          }
          return result;
        }
      });
      final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA256));
      signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
      try( BCPGOutputStream outputStream = new BCPGOutputStream( new ArmoredOutputStream(signature)) ) {
        IOUtils.process(message, new IOUtils.StreamHandler() {

          @Override
          public void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException {
            signatureGenerator.update(buffer, offset, length);
          }

        });
        signatureGenerator.generate().encode(outputStream);
      }
      result = true;
    } catch (IOException e) {
      e.printStackTrace();
    } catch (PGPException e) {
      e.printStackTrace();
    }
    return result;
  }
}
