package com.example.clientauthorizationcode.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.GatewayFilterSpec;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {
      @Bean
      RouteLocator gateway(RouteLocatorBuilder routeLocatorBuilder) {
            return routeLocatorBuilder
                  .routes()
                  /** http://localhost:8081 - resource server*/
                  .route(predicateSpec -> predicateSpec
                        .path("/admin", "/user", "/")
                        .filters(GatewayFilterSpec::tokenRelay)
                        .uri("http://localhost:8081")
                  )
                  .build();
      }
}
