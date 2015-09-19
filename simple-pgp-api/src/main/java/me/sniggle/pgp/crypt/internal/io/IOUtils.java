package me.sniggle.pgp.crypt.internal.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Created by iulius on 19/09/15.
 */
public class IOUtils {

  private static final int BUFFER_SIZE = 4096;

  public interface StreamHandler {

    void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException;

  }

  public static void copy(InputStream inputStream, OutputStream outputStream) throws IOException {
    copy(inputStream, outputStream, new byte[BUFFER_SIZE]);
  }

  public static void copy(InputStream inputStream, OutputStream outputStream, byte[] buffer) throws IOException {
    copy(inputStream, outputStream, buffer, null);
  }

  public static void copy(InputStream inputStream, final OutputStream outputStream, byte[] buffer, final StreamHandler addtionalHandling) throws IOException {
    process(inputStream, new StreamHandler() {
      @Override
      public void handleStreamBuffer(byte[] buffer, int offset, int length) throws IOException {
        outputStream.write(buffer, offset, length);
        if( addtionalHandling != null ) {
          addtionalHandling.handleStreamBuffer(buffer, offset, length);
        }
      }

    }, new byte[BUFFER_SIZE]);
  }

  public static void process(InputStream inputStream, StreamHandler handler) throws IOException {
    process(inputStream, handler, new byte[BUFFER_SIZE]);
  }

  public static void process(InputStream inputStream, StreamHandler handler, byte[] buffer) throws IOException {
    int read = -1;
    while( (read = inputStream.read(buffer)) != -1 ) {
      handler.handleStreamBuffer(buffer, 0, read);
    }
  }

}
