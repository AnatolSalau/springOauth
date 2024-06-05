package com.example.clientcredentialflow.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Map;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;


@RestController
public class AuthorizationController {

      private final WebClient webClient;

      private final String messagesBaseUri;

      public AuthorizationController(WebClient webClient,
                                     @Value("${messages.base-uri}") String messagesBaseUri) {
            this.webClient = webClient;
            this.messagesBaseUri = messagesBaseUri;
      }

      /**
       * Method for clientCredential
       * http://127.0.0.1:8080
       * Postman url : http://localhost:8080/authorize?grant_type=client_credentials
       */
      @GetMapping(value = "/authorize", params = "grant_type=client_credentials")
      public Map<String, String> clientCredentialsGrant() {
            Map<String, String> messages = this.webClient
                  .get()
                  .uri(this.messagesBaseUri)
                  .attributes(clientRegistrationId("spring"))
                  .retrieve()
                  .bodyToMono(Map.class)
                  .block();
            return messages;
      }
}
