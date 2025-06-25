package ru.stitchonfire.sso.security.service;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.SecretGenerator;
import com.bastiaanjansen.otp.TOTPGenerator;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Base64;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class TotpService {

    private static final String ISSUER = "SSO-APP";

    public String generateBase32Secret() {
        byte[] rawSecret = SecretGenerator.generate();
        return new Base32().encodeToString(rawSecret);
    }

    public String buildOtpAuthUri(String base32Secret) {
        byte[] rawSecret = new Base32().decode(base32Secret);
        TOTPGenerator totpGenerator = new TOTPGenerator.Builder(rawSecret)
                .withHOTPGenerator(builder -> {
                    builder.withPasswordLength(6);
                    builder.withAlgorithm(HMACAlgorithm.SHA256);
                })
                .withPeriod(Duration.ofSeconds(30))
                .build();

        try {
            return totpGenerator.getURI(ISSUER).toString();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateQrCodeDataUri(String otpAuthUri) throws Exception {
        BitMatrix matrix = new MultiFormatWriter()
                .encode(otpAuthUri, BarcodeFormat.QR_CODE, 240, 240);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
            String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());
            return "data:image/png;base64," + b64;
        }
    }

    public boolean verifyCodeWithSecret(String base32Secret, int code) {
        TOTPGenerator totpGenerator = new TOTPGenerator.Builder(new Base32().decode(base32Secret))
                .withHOTPGenerator(builder -> {
                    builder.withPasswordLength(6);
                    builder.withAlgorithm(HMACAlgorithm.SHA256);
                })
                .withPeriod(Duration.ofSeconds(30))
                .build();

        return totpGenerator.verify(String.format("%06d", code));
    }



}
