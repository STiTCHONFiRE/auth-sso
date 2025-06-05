package ru.stitchonfire.sso.security.auth.process.totp;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TotpController {

    @GetMapping("/mfa")
    public String authenticator() {
        return "mfa";
    }

}
