# 手動Build手順

``` sh
./gradlew bootBuildImage --imageName=ablankz/nova-auth-service:1.0.4
docker push ablankz/nova-auth-service:1.0.4
```