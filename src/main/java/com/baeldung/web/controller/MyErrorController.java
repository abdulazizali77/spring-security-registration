package com.baeldung.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.LocaleResolver;

import javax.servlet.http.HttpServletRequest;
import java.util.Locale;

@Controller
public class MyErrorController {
    @Autowired
    MessageSource messageSource;
    @Autowired
    private LocaleResolver localeResolver;

    @RequestMapping("/error.html")
    public String loginError(HttpServletRequest httpServletRequest, Model model) {
        Locale locale = localeResolver.resolveLocale(httpServletRequest);
        //FIXME: null check?
        String requestURI = (String) httpServletRequest.getSession().getAttribute("temp");
        String message = messageSource.getMessage("message.customError", new Object[]{requestURI}, locale);
        httpServletRequest.getSession().setAttribute("temp", "");
        model.addAttribute("customError", message);
        return "error.html";
    }
}
