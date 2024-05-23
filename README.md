https://stackoverflow.com/questions/75763382/how-to-get-scope-and-roles-in-oauth2-2-1-spring-boot-resource-server

https://medium.com/@alperkrtglu/spring-oauth2-with-keycloak-moving-from-scope-to-roles-34247f3ff78e

https://stackoverflow.com/questions/75763382/how-to-get-scope-and-roles-in-oauth2-2-1-spring-boot-resource-server

https://medium.com/@alperkrtglu/spring-oauth2-with-keycloak-moving-from-scope-to-roles-34247f3ff78e


Ports old
    Authorization service               8080
    Resource service                    8081
    Client Authorization code service   8082
    Client Credential service           8083


Ports new
    Authorization service               8080 -> 8082
    Resource service                    8081 -> 8083
    Client Authorization code service   8082 -> 8081
    Client Credential service           8083 -> 8080


