package me.sniggle.pgp.crypt;

import me.sniggle.pgp.crypt.internal.BasePGPCommon;
import me.sniggle.pgp.crypt.internal.io.IOUtils;
import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.BCPGOutputStream;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.openpgp.*;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

/**
 * Created by iulius on 18/09/15.
 */
public class PGPMessageSigner extends BasePGPCommon implements MessageSigner {

  @Override
  public boolean verifyMessage(InputStream publicKey, InputStream message, InputStream signatureStream) {
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
            PGPPublicKey pgpPublicKey = findPublicKey(publicKey, new KeyFilter<PGPPublicKey>() {
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

  @Override
  public boolean signMessage(InputStream privateKeyOfSender, final String userIdForPrivateKey, String passwordOfPrivateKey, InputStream message, OutputStream signedMessage) {
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
      try( BCPGOutputStream outputStream = new BCPGOutputStream( new ArmoredOutputStream(signedMessage)) ) {
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
