package me.sniggle.pgp.crypt;

import me.sniggle.pgp.crypt.internal.BasePGPCommon;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.Iterator;

/**
 * The the library dependent implementation of a MessageEncryptor
 *
 * @author iulius
 */
public class PGPMessageEncryptor extends BasePGPCommon implements MessageEncryptor {

  public PGPMessageEncryptor() {
  }

  /**
   * encrypts and if possible (secret key and password provided) signs the target stream
   *
   * @param pgpSecretKey
   *    the secret key
   * @param password
   *    the password for the private key
   * @param inputDataName
   *    the name of the data
   * @param inputData
   *    the plain input data
   * @param encryptedDataStream
   *    the encrypted data stream
   * @throws PGPException
   * @throws IOException
   */
  private void encryptAndSign(PGPSecretKey pgpSecretKey, String password, String inputDataName, InputStream inputData, OutputStream encryptedDataStream) throws PGPException, IOException {
    PGPSignatureGenerator pgpSignatureGenerator = null;

    PGPPrivateKey signingKey = null;
    if (pgpSecretKey != null) {
      signingKey = findPrivateKey(pgpSecretKey, password);
    }

    PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(getCompressionAlgorithm());
    try ( OutputStream compressedDataStream = new BCPGOutputStream(compressedDataGenerator.open(encryptedDataStream)) ) {

      if (pgpSecretKey != null) {
        pgpSignatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(signingKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA256));
        pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingKey);
        pgpSignatureGenerator.generateOnePassVersion(false).encode(compressedDataStream);
      }

      PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator(false);
      try (OutputStream literalDataOutputStream = literalDataGenerator.open(compressedDataStream, PGPLiteralDataGenerator.BINARY, inputDataName, new Date(), new byte[4096])) {

        byte[] buffer = new byte[4096];
        int read = -1;

        while ((read = inputData.read(buffer)) != -1) {
          literalDataOutputStream.write(buffer, 0, read);
          if (pgpSecretKey != null) {
            pgpSignatureGenerator.update(buffer, 0, read);
          }
        }

        literalDataGenerator.close();
      }
      if (pgpSecretKey != null) {
        pgpSignatureGenerator.generate().encode(compressedDataStream);
      }
      compressedDataGenerator.close();
    }
  }

  /**
   * accessor to the encryption algorithm constant to use, based of #isUnlimitedEncryptionStrength()
   *
   * @return the appropriate algorithm constant
   */
  protected  int getEncryptionAlgorithm() {
    return (isUnlimitedEncryptionStrength()) ? PGPEncryptedData.AES_256 : PGPEncryptedData.AES_128;
  }

  /**
   * @see MessageEncryptor#encrypt(InputStream, String, InputStream, OutputStream)
   *
   * @param publicKeyOfRecipient
   *    the public key stream of the message recipient
   * @param inputDataName
   *    the (file)name of the input data
   * @param plainInputData
   *    the input data stream
   * @param target
   *    the encrypted (ascii-armored) target stream
   * @return
   */
  @Override
  public boolean encrypt(InputStream publicKeyOfRecipient, String inputDataName, InputStream plainInputData, OutputStream target) {
    return encrypt(publicKeyOfRecipient, null, null, null, inputDataName, plainInputData, target);
  }

  /**
   * @see MessageEncryptor#encrypt(InputStream, InputStream, String, String, String, InputStream, OutputStream)
   *
   * @param publicKeyOfRecipient
   *    the public key stream of the message recipient
   * @param privateKeyOfSender
   *    the private key stream of the message sender
   * @param userIdOfSender
   *    the user id of the message sender
   * @param passwordOfSendersPrivateKey
   *    the password for the private key of the sender
   * @param inputDataName
   *    the (file)name of the input data
   * @param plainInputData
   *    the input data stream
   * @param target
   *    the encrypted (ascii-armored) target stream
   * @return
   */
  @Override
  public boolean encrypt(InputStream publicKeyOfRecipient, InputStream privateKeyOfSender, String userIdOfSender, String passwordOfSendersPrivateKey, String inputDataName, InputStream plainInputData, OutputStream target) {
    boolean result = true;
    PGPPublicKey pgpPublicKey = findPublicKey(publicKeyOfRecipient, new KeyFilter<PGPPublicKey>() {
      @Override
      public boolean accept(PGPPublicKey pgpKey) {
        return pgpKey.isEncryptionKey() && !pgpKey.isMasterKey();
      }
    });
    if( pgpPublicKey != null ) {
      try( OutputStream wrappedTargetStream = new ArmoredOutputStream(target) ) {
        BcPGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(getEncryptionAlgorithm());
        encryptorBuilder.setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
        PGPSecretKey pgpSecretKey = null;
        if( privateKeyOfSender != null ) {
          pgpSecretKey = findSecretKey(privateKeyOfSender, userIdOfSender);
        }
        try( OutputStream encryptedDataStream = encryptedDataGenerator.open(wrappedTargetStream, new byte[4096]) ) {
          encryptAndSign(pgpSecretKey, passwordOfSendersPrivateKey, inputDataName, plainInputData, encryptedDataStream);
        }
      } catch (IOException | PGPException e) {
        result &= false;
      }
    }
    return result;
  }

  /**
   * @see MessageEncryptor#decrypt(String, InputStream, InputStream, OutputStream)
   *
   * @param passwordOfReceiversPrivateKey
   *    the password for the receiver's private key
   * @param privateKeyOfReceiver
   *    the receiver's private key
   * @param encryptedData
   *    the encrypted data
   * @param target
   *    the plain data stream
   * @return
   */
  @Override
  public boolean decrypt(String passwordOfReceiversPrivateKey, InputStream privateKeyOfReceiver, InputStream encryptedData, OutputStream target) {
    return decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, null, encryptedData, target);
  }

  /**
   * @see MessageEncryptor#decrypt(String, InputStream, InputStream, InputStream, OutputStream)
   *
   * @param passwordOfReceiversPrivateKey
   *    the password of the receivers private key
   * @param privateKeyOfReceiver
   *    the receiver's private key
   * @param publicKeyOfSender
   *    the sender's public key
   * @param encryptedData
   *    the encrypted data
   * @param target
   *    the plain data stream
   * @return
   */
  @Override
  public boolean decrypt(String passwordOfReceiversPrivateKey, InputStream privateKeyOfReceiver, InputStream publicKeyOfSender, InputStream encryptedData, OutputStream target) {
    boolean result = true;
    try {
      PGPPublicKeyRingCollection publicKeyRingCollection = null;
      if( publicKeyOfSender != null ) {
        publicKeyRingCollection = new PGPPublicKeyRingCollection(new ArmoredInputStream(publicKeyOfSender), new BcKeyFingerprintCalculator());
      }
      try( InputStream in = PGPUtil.getDecoderStream(encryptedData) ) {
        PGPObjectFactory objectFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList dataList;

        Object firstObject = objectFactory.nextObject();
        if( firstObject instanceof PGPEncryptedDataList ) {
          dataList = (PGPEncryptedDataList)firstObject;
        } else {
          dataList = (PGPEncryptedDataList)objectFactory.nextObject();
        }
        Iterator<PGPEncryptedData> iterator = dataList.getEncryptedDataObjects();
        PGPPrivateKey pgpPrivateKey = null;
        PGPEncryptedData pgpEncryptedData = null;
        while( pgpPrivateKey == null && ((pgpEncryptedData = iterator.next()) != null) ) {
          pgpPrivateKey = findPrivateKey(privateKeyOfReceiver, ((PGPPublicKeyEncryptedData)pgpEncryptedData).getKeyID(), passwordOfReceiversPrivateKey);
        }
        PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory = new BcPublicKeyDataDecryptorFactory(pgpPrivateKey);
        try( InputStream clearText = ((PGPPublicKeyEncryptedData)pgpEncryptedData).getDataStream(publicKeyDataDecryptorFactory)) {
          PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(clearText, new BcKeyFingerprintCalculator());
          Object message = pgpObjectFactory.nextObject();
          PGPCompressedData compressedData;
          PGPOnePassSignatureList onePassSignatureList = null;
          PGPOnePassSignature onePassSignature = null;
          PGPLiteralData literalData;
          PGPSignatureList signatures = null;
          PGPPublicKey pgpPublicKey = null;

          if( message instanceof PGPCompressedData ) {
            compressedData = (PGPCompressedData) message;
            pgpObjectFactory = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
          }
          while( (message = pgpObjectFactory.nextObject()) != null ) {
            if( message instanceof PGPLiteralData ) {
              literalData = (PGPLiteralData) message;
              try( InputStream literalDataStream = literalData.getInputStream() ) {
                byte[] buffer = new byte[4096];
                int read = -1;
                while( (read = literalDataStream.read(buffer)) != -1 ) {
                  if (onePassSignature != null) {
                    onePassSignature.update(buffer, 0, read);
                  }
                  target.write(buffer, 0, read);
                }
              }
            } else if( message instanceof PGPOnePassSignatureList ) {
              onePassSignatureList = (PGPOnePassSignatureList)message;
              onePassSignature = onePassSignatureList.get(0);
              if( publicKeyOfSender != null ) {
                pgpPublicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
                onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
              }
            } else if( message instanceof  PGPSignatureList){
              signatures = (PGPSignatureList)message;
            }
          }

          for( int i = 0; onePassSignatureList != null && i < onePassSignatureList.size(); i++ ) {
            if( pgpPublicKey != null && signatures != null ) {
              PGPSignature signature = signatures.get(i);
              byte[] onePassSignatureBytes = onePassSignature.getEncoded();
              byte[] signatureBytes = signature.getSignature();
              if( onePassSignature.verify(signature) ) {
                String userId = null;
                Iterator<String> it = pgpPublicKey.getUserIDs();
                while (it.hasNext()) {
                  System.out.println(it.next());
                }
              } else {
                result &= false;
              }
            } else {
              result &= false;
            }
          }


          if( pgpEncryptedData.isIntegrityProtected() ) {
            if( pgpEncryptedData.verify() ) {

            } else {
              result &= false;
            }
          }
        }
      }
    } catch (IOException | PGPException e) {
      e.printStackTrace();
      result &= false;
    }
    return result;
  }
}
