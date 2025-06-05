package ru.stitchonfire.sso.security.auth.process.face;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class FaceController {

    @GetMapping("/face")
    public String getFace() {
        return "face";
    }

}
