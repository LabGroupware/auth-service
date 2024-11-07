# Account

## OAuth Service

### Only Setup
``` sh
sudo chmod +x ./init.sh ./down.sh 
```

起動
``` sh
./init.sh
```

停止
``` sh
./down.sh
```

### Front Development
``` sh
npx tailwindcss -i ./src/main/resources/static/css/input.css -o ./src/main/resources/static/css/output.css --watch
```

### Environment
- CUSTOM_SECRET: 適当な文字列
- JWT_SECRET: JWTの署名に使用する文字列

### Prerequire
- [asdf](./setup_asdf.md)

### Migrationファイル生成
``` sh
./gradlew generateMigrationFile -PmigrationName={ファイル内容} -Pdir={相対ディレクトリ}
```

具体例
``` sh
./gradlew generateMigrationFile -PmigrationName=create_users_table -Pdir=ddl
```

### Setup
#### コマンドセットアップ
``` sh
asdf plugin add grpcurl
asdf plugin add kafka
asdf install
```
