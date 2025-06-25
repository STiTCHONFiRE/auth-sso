package ru.stitchonfire.sso.controller;

import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import ru.stitchonfire.sso.dto.RegistrationDto;
import ru.stitchonfire.sso.security.service.CustomerUserDetailsService;
import ru.stitchonfire.sso.security.service.OidcUserInfoService;
import ru.stitchonfire.sso.security.service.TotpService;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Base64;

@Controller
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class RegistrationController {

    TotpService totpService;
    UserDetailsService userDetailsService;

    OidcUserInfoService oidcUserInfoService;

    @GetMapping("/registration")
    public String registration(Model model) {
        String base32Secret = totpService.generateBase32Secret();
        String otpAuthUri = totpService.buildOtpAuthUri(base32Secret);

        try {
            String qrDataUri = totpService.generateQrCodeDataUri(otpAuthUri);

            model.addAttribute("dto", new RegistrationDto());
            model.addAttribute("qr", qrDataUri);
            model.addAttribute("secret", base32Secret);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return "registration";
    }

    @PostMapping("/registration")
    public String registerUser(
            @Valid @ModelAttribute("dto")
            RegistrationDto dto,
            BindingResult br
    ) throws Exception {
        if (br.hasErrors()) {
            return "registration";
        }

        boolean valid = totpService.verifyCodeWithSecret(dto.getSecretKey(), dto.getCode());
        if (!valid) {
            br.rejectValue("code", "invalid", "Неверный код Google Authenticator");
            return "registration";
        }

        try (InputStream in  = dto.getFaceFile().getInputStream();
             OutputStream out = new ByteArrayOutputStream()) {

            Base64.Encoder encoder = Base64.getEncoder();
            try (OutputStream base64Out = encoder.wrap(out)) {
                in.transferTo(base64Out);
            }

            String base64 = out.toString();

            CustomerUserDetailsService customerUserDetailsService = (CustomerUserDetailsService) userDetailsService;
            customerUserDetailsService.createUsers(
                    dto.getLogin(),
                    dto.getPassword(),
                    dto.getSecretKey(),
                    dto.getSecretQuestion(),
                    dto.getSecretAnswer(),
                    base64
            );

            oidcUserInfoService.createUser(dto.getLogin());
        }

        return "redirect:http://localhost:4200";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
