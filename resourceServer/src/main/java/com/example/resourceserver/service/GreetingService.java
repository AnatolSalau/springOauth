package com.example.resourceserver.service;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class GreetingService {
      public Map<String, String> greet() {
            Jwt principal = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            return Map.of("authority : SCOPE_user.read", "message " + principal.getSubject());
      }
}
