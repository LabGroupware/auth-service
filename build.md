# 手動Build手順

``` sh
BUILD_VERSION=1.0.4
./gradlew jibMultiBuild -PimageVersion=$BUILD_VERSION
docker push ablankz/nova-auth-service:$BUILD_VERSION-amd64
docker push ablankz/nova-auth-service:$BUILD_VERSION-arm64
```