# 手動Build手順

``` sh
./gradlew bootBuildImage --imageName=ablankz/nova-auth-service:1.0.0
docker push ablankz/nova-auth-service:1.0.0
```