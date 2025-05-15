package ru.stitchonfire.sso.security.auth.process.mfa;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MFAController {

    @GetMapping("/mfa")
    public String authenticator() {
        return "mfa";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
