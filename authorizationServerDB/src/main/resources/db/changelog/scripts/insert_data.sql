-- insert client to clients
with new_client_uuid (id) as (
       select gen_random_uuid()
)
INSERT INTO oauth.oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types, redirect_uris,
    scopes, client_settings, token_settings)
VALUES (
           (SELECT id FROM  new_client_uuid), 'client', current_timestamp, '$2a$12$Ah/6RpokivnYEYhFy58pWeAt/3YZB7qtK6fH05tLoWXCTywgtFGOe',
           (SELECT id FROM  new_client_uuid),'client_secret_basic', 'refresh_token,client_credentials,authorization_code',
           'https://springone.io/authorized,http://127.0.0.1:8081/login/oauth2/code/spring,https://oidcdebugger.com/debug,https://oauthdebugger.com/debug',
           'user.read,user.write,openid,roles',
           '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
           '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.x509-certificate-bound-access-tokens":false,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
);

-- insert client2 to clients
with new_client_uuid (id) as (
    select gen_random_uuid()
)
INSERT INTO oauth.oauth2_registered_client (
    id, client_id, client_id_issued_at, client_secret, client_name,
    client_authentication_methods, authorization_grant_types, redirect_uris,
    scopes, client_settings, token_settings)
VALUES (
           (SELECT id FROM  new_client_uuid), 'client2', current_timestamp, '$2a$12$OSv.3I9LIJ2Q1si9UmATwODq.JCykmUVkXpVVRBUXf9DHvILM2SFq',
           (SELECT id FROM  new_client_uuid),'client_secret_basic', 'refresh_token,client_credentials,authorization_code',
           'https://springone.io/authorized,http://127.0.0.1:8081/login/oauth2/code/spring,https://oidcdebugger.com/debug,https://oauthdebugger.com/debug',
           'user.read,user.write,openid,roles',
           '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":false}',
           '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.x509-certificate-bound-access-tokens":false,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}'
       );

-- insert user to users

INSERT INTO oauth.users (username, password, enabled)
VALUES ('user', '$2a$12$aq7XSTeOelMHY9nG1CPeS.CBz/5TnKiazEVzfOBmFF4dOtx5Odryi', true),
       ('admin', '$2a$12$WpqXTZTHpYh/PqG5pfnWfuvN/yKxoJWSXHC3MWODY4LiOcYodixFm', true);

INSERT INTO oauth.authorities (username, authority)
VALUES ('user', 'ROLE_USER'),
       ('admin', 'ROLE_ADMIN');