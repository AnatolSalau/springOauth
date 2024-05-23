package com.example.resourceserver.controller;


import com.example.resourceserver.service.GreetingService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
@ResponseBody
public class GreetingController {

      private final GreetingService greetingService;

      @Autowired
      public GreetingController(GreetingService greetingService) {
            this.greetingService = greetingService;
      }

      @GetMapping("/")
      Map<String,String> sayHello(@AuthenticationPrincipal Jwt jwt, Authentication authentication) {
            Map<String, String> result = new HashMap<>( Map.of(
                  "hello", "from sayHello",
                  "message", "Hello : " + jwt.getSubject(),
                  "authority", "Authorities :  " + authentication.getAuthorities()
            ));
            result.putAll(greetingService.greet());

            return result;
      }

      @GetMapping("/admin")
      //@PreAuthorize("hasAuthority('SCOPE_user.read')")
      @PreAuthorize("hasRole('ROLE_ROLE_ADMIN')")
      Map<String,String> sayHelloAdmin(@AuthenticationPrincipal Jwt jwt, Authentication authentication) {
            Map<String, String> result = new HashMap<>( Map.of(
                  "hello", "from sayHelloAdmin",
                  "message", "Hello : " + jwt.getSubject(),
                  "authority", "Authorities :  " + authentication.getAuthorities()
            ));
            result.putAll(greetingService.greet());

            return result;
      }

      @GetMapping("/user")
      //@PreAuthorize("hasAuthority('SCOPE_user.read')")
      @PreAuthorize("hasRole('ROLE_ROLE_USER')")
      Map<String,String> sayHelloUser(@AuthenticationPrincipal Jwt jwt, Authentication authentication) {
            Map<String, String> result = new HashMap<>( Map.of(
                  "hello", "from sayHelloUser",
                  "message", "Hello : " + jwt.getSubject(),
                  "authority", "Authorities :  " + authentication.getAuthorities()
            ));
            result.putAll(greetingService.greet());

            return result;
      }
}
