package ru.stitchonfire.sso.dto;

import jakarta.validation.constraints.Digits;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Data;
import lombok.experimental.FieldDefaults;
import org.springframework.web.multipart.MultipartFile;

@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
public class RegistrationDto {
        @NotBlank
        String login;

        @NotBlank
        String password;

        @Digits(integer = 6, fraction = 0)
        Integer code;

        @NotBlank
        String secretQuestion;

        @NotBlank
        String secretAnswer;

        @NotBlank
        String secretKey;

        @NotNull
        MultipartFile faceFile;
}
