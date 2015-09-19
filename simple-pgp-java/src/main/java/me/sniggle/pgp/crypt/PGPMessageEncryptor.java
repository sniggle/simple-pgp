package me.sniggle.pgp.crypt;

import me.sniggle.pgp.crypt.internal.BasePGPCommon;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Created by iulius on 16/09/15.
 */
public class PGPMessageEncryptor extends BasePGPCommon implements MessageEncryptor {

  public PGPMessageEncryptor() {
  }

  private void encryptAndSign(PGPSecretKey pgpSecretKey, String password, String inputDataName, InputStream inputData, OutputStream encryptedDataStream) throws PGPException, IOException {
    PGPSignatureGenerator pgpSignatureGenerator = null;

    PGPPrivateKey signingKey = findPrivateKey(pgpSecretKey, password);

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

  protected  int getEncryptionAlgorithm() {
    return (isUnlimitedEncryptionStrength()) ? PGPEncryptedData.AES_256 : PGPEncryptedData.AES_128;
  }

  @Override
  public boolean encrypt(InputStream publicKey, String inputDataName, InputStream inputData, OutputStream target) {
    return encrypt(publicKey, null, null, null, inputDataName, inputData, target);
  }

  @Override
  public boolean encrypt(InputStream publicKey, InputStream privateKey, String userId, String password, String inputDataName, InputStream inputData, OutputStream target) {
    boolean result = true;
    PGPPublicKey pgpPublicKey = findPublicKey(publicKey, new KeyFilter<PGPPublicKey>() {
      @Override
      public boolean accept(PGPPublicKey pgpKey) {
        return pgpKey.isEncryptionKey();
      }
    });
    if( pgpPublicKey != null ) {
      try( OutputStream wrappedTargetStream = new ArmoredOutputStream(target) ) {
        BcPGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(getEncryptionAlgorithm());
        encryptorBuilder.setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
        PGPSecretKey pgpSecretKey = findSecretKey(privateKey, userId);
        try( OutputStream encryptedDataStream = encryptedDataGenerator.open(wrappedTargetStream, new byte[4096]) ) {
          encryptAndSign(pgpSecretKey, password, inputDataName, inputData, encryptedDataStream);
        }
      } catch (IOException | PGPException e) {
        result &= false;
      }
    }
    return result;
  }

  @Override
  public boolean decrypt(String password, InputStream privateKey, InputStream encryptedData, OutputStream target) {
    return decrypt(password, privateKey, null, encryptedData, target);
  }

  @Override
  public boolean decrypt(String password, InputStream privateKey, InputStream publicKey, InputStream encryptedData, OutputStream target) {
    boolean result = true;
    try {
      PGPPublicKeyRingCollection publicKeyRingCollection = null;
      if( publicKey != null ) {
        publicKeyRingCollection = new PGPPublicKeyRingCollection(new ArmoredInputStream(publicKey), new BcKeyFingerprintCalculator());
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
          pgpPrivateKey = findPrivateKey(privateKey, ((PGPPublicKeyEncryptedData)pgpEncryptedData).getKeyID(), password);
        }
        try( InputStream clearText = ((PGPPublicKeyEncryptedData)pgpEncryptedData).getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey))) {
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
              if( publicKey != null ) {
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
                  //System.out.println(it.next());
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
