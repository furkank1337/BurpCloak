package aimasker.core.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/** Transfer- and content-coding decoders, bounded to resist decompression bombs. */
final class BodyCodecs {

    static final int MAX_DECODED_BYTES = 64 * 1024 * 1024;

    private BodyCodecs() {
    }

    /** Decodes a chunked body (Latin-1 string). Empty when malformed. Trailers are dropped. */
    static Optional<String> dechunk(String body) {
        StringBuilder out = new StringBuilder(body.length());
        int pos = 0;
        while (true) {
            int lineEnd = body.indexOf('\n', pos);
            if (lineEnd < 0) {
                return Optional.empty();
            }
            String sizeLine = body.substring(pos, lineEnd).trim();
            int extension = sizeLine.indexOf(';');
            if (extension >= 0) {
                sizeLine = sizeLine.substring(0, extension).trim();
            }
            int size;
            try {
                size = Integer.parseInt(sizeLine, 16);
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
            if (size < 0 || out.length() + (long) size > MAX_DECODED_BYTES) {
                return Optional.empty();
            }
            int dataStart = lineEnd + 1;
            if (size == 0) {
                return Optional.of(out.toString());
            }
            if (dataStart + size > body.length()) {
                return Optional.empty();
            }
            out.append(body, dataStart, dataStart + size);
            pos = dataStart + size;
            if (body.startsWith("\r\n", pos)) {
                pos += 2;
            } else if (body.startsWith("\n", pos)) {
                pos += 1;
            } else {
                return Optional.empty();
            }
        }
    }

    static Optional<String> gunzip(String body) {
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(latin1(body)))) {
            return readBounded(in);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /** HTTP "deflate" is meant to be zlib-wrapped, but raw deflate is common in practice. */
    static Optional<String> inflate(String body) {
        for (boolean raw : new boolean[] {false, true}) {
            Inflater inflater = new Inflater(raw);
            try (InputStream in = new InflaterInputStream(new ByteArrayInputStream(latin1(body)), inflater)) {
                Optional<String> result = readBounded(in);
                if (result.isPresent()) {
                    return result;
                }
            } catch (IOException e) {
                // try the next variant
            } finally {
                inflater.end();
            }
        }
        return Optional.empty();
    }

    private static Optional<String> readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[16 * 1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            if (out.size() + read > MAX_DECODED_BYTES) {
                return Optional.empty();
            }
            out.write(buffer, 0, read);
        }
        return Optional.of(new String(out.toByteArray(), StandardCharsets.ISO_8859_1));
    }

    private static byte[] latin1(String text) {
        return text.getBytes(StandardCharsets.ISO_8859_1);
    }
}
