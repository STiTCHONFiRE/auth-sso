package ru.stitchonfire.sso.security.auth.process.question;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import ru.stitchonfire.sso.security.auth.provider.NoCompletedAuthenticationToken;
import ru.stitchonfire.sso.security.model.User;

@Controller
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class QuestionController {

    @GetMapping("/question")
    public String authenticator(Model model) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof NoCompletedAuthenticationToken token) {
            if (token.getPrincipal() instanceof User u) {
                model.addAttribute("question", u.getQuestion());
            }
        } else {
            model.addAttribute("question", "Какой ваш любимый цвет?");
        }

        return "question";
    }

}
