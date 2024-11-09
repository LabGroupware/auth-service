package org.cresplanex.account.oauth.controller.api;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;
import org.cresplanex.account.oauth.dto.api.ResponseDto;
import org.cresplanex.account.oauth.dto.api.oauth2RegisteredClient.Oauth2RegisteredClientCredentialsResponseDto;
import org.cresplanex.account.oauth.dto.api.oauth2RegisteredClient.Oauth2RegisteredClientRequestDto;
import org.cresplanex.account.oauth.dto.api.oauth2RegisteredClient.Oauth2RegisteredClientResponseDto;
import org.cresplanex.account.oauth.entity.Oauth2RegisteredClientEntity;
import org.cresplanex.account.oauth.service.Oauth2RegisteredClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@AllArgsConstructor
@RequestMapping("/api/oauth-clients")
public class Oauth2RegisteredClientController {

    private final Oauth2RegisteredClientService service;

    // クライアント作成
    @PostMapping
    public ResponseEntity<ResponseDto<Oauth2RegisteredClientCredentialsResponseDto>> createClient(
           @Valid @RequestBody Oauth2RegisteredClientRequestDto requestDTO
    ) {
        // リクエストDTOをエンティティに変換
        Oauth2RegisteredClientEntity client = toEntity(requestDTO);

        // クライアント登録
        Oauth2RegisteredClientCredentialsResponseDto responseDTO = toCredentialResponseDTO(
                service.createClient(
                        client,
                        requestDTO.getAuthorizationGrantTypes(),
                        requestDTO.getClientAuthenticationMethods(),
                        requestDTO.getScopes(),
                        requestDTO.getRedirectUris(),
                        requestDTO.getPostLogoutRedirectUris()
                ));

        // レスポンスDTOを作成
        ResponseDto<Oauth2RegisteredClientCredentialsResponseDto> response = new ResponseDto<>();
        response.setSuccess(true);
        response.setData(responseDTO);
        response.setCode(AuthServerErrorCode.SUCCESS);
        response.setCaption("Client created successfully.");

        // エンティティをレスポンスDTOに変換
        return ResponseEntity.ok(response);
    }

    // 取得
    // 削除
    // 更新
    // 一覧取得
    // クレデンシャル再発行

//    // クライアント取得（ID指定）
//    @GetMapping("/{id}")
//    public ResponseEntity<ResponseDto<Oauth2RegisteredClientResponseDto>> getClientById(@PathVariable String id) {
//        return service.getClientById(id)
//                .map(this::toResponseDTO) // エンティティをレスポンスDTOに変換
//                .map(ResponseEntity::ok)
//                .orElse(ResponseEntity.notFound().build());
//    }
//
//    // クライアント取得（Client ID指定）
//    @GetMapping("/client-id/{clientId}")
//    public ResponseEntity<ResponseDto<Oauth2RegisteredClientResponseDto>> getClientByClientId(@PathVariable String clientId) {
//        return service.getClientByClientId(clientId)
//                .map(this::toResponseDTO) // エンティティをレスポンスDTOに変換
//                .map(ResponseEntity::ok)
//                .orElse(ResponseEntity.notFound().build());
//    }
//
//    // クライアント一覧取得
//    @GetMapping
//    public ResponseEntity<ResponseDto<List<Oauth2RegisteredClientResponseDto>>> getAllClients() {
//        List<Oauth2RegisteredClientResponseDto> clients = service.getAllClients().stream()
//                .map(this::toResponseDTO) // エンティティをレスポンスDTOに変換
//                .collect(Collectors.toList());
//        return ResponseEntity.ok(clients);
//    }
//
//    // クライアント更新
//    @PutMapping("/{id}")
//    public ResponseEntity<ResponseDto<Oauth2RegisteredClientResponseDto>> updateClient(@PathVariable String id, @RequestBody Oauth2RegisteredClientRequestDto requestDTO) {
//        try {
//            // リクエストDTOをエンティティに変換
//            Oauth2RegisteredClientEntity updatedEntity = toEntity(requestDTO);
//
//            // 更新処理
//            Oauth2RegisteredClientEntity updatedClient = service.updateClient(id, updatedEntity);
//
//            // エンティティをレスポンスDTOに変換
//            return ResponseEntity.ok(toResponseDTO(updatedClient));
//        } catch (RuntimeException e) {
//            return ResponseEntity.notFound().build();
//        }
//    }
//
//    // クライアント削除
//    @DeleteMapping("/{id}")
//    public ResponseEntity<ResponseDto<Object>> deleteClient(@PathVariable String id) {
//        try {
//            service.deleteClient(id);
//            return ResponseEntity.noContent().build();
//        } catch (RuntimeException e) {
//            return ResponseEntity.notFound().build();
//        }
//    }

    // DTO → エンティティ変換
    private Oauth2RegisteredClientEntity toEntity(Oauth2RegisteredClientRequestDto dto) {
        Oauth2RegisteredClientEntity client = new Oauth2RegisteredClientEntity();
        client.setClientName(dto.getClientName());
        client.setClientAuthenticationMethods(String.join(",", dto.getClientAuthenticationMethods()));
        client.setAuthorizationGrantTypes(String.join(",", dto.getAuthorizationGrantTypes()));
        client.setScopes(String.join(",", dto.getScopes()));
        client.setRedirectUris(dto.getRedirectUris() != null ? String.join(",", dto.getRedirectUris()) : null);
        client.setPostLogoutRedirectUris(dto.getPostLogoutRedirectUris() != null ? String.join(",", dto.getPostLogoutRedirectUris()) : null);
        client.setClientSettings("{}"); // 初期値を設定
        client.setTokenSettings("{}"); // 初期値を設定
        return client;
    }

    // エンティティ → レスポンスDTO変換
    private Oauth2RegisteredClientResponseDto toResponseDTO(Oauth2RegisteredClientEntity client) {
        Oauth2RegisteredClientResponseDto dto = new Oauth2RegisteredClientResponseDto();
        dto.setId(client.getId());
        dto.setClientId(client.getClientId());
        dto.setClientIdIssuedAt(client.getClientIdIssuedAt());
        dto.setClientName(client.getClientName());
        dto.setClientAuthenticationMethods(List.of(client.getClientAuthenticationMethods().split(",")));
        dto.setAuthorizationGrantTypes(List.of(client.getAuthorizationGrantTypes().split(",")));
        dto.setScopes(List.of(client.getScopes().split(",")));
        dto.setRedirectUris(client.getRedirectUris() != null ? List.of(client.getRedirectUris().split(",")) : null);
        dto.setPostLogoutRedirectUris(client.getPostLogoutRedirectUris() != null ? List.of(client.getPostLogoutRedirectUris().split(",")) : null);
        dto.setClientSecretExpiresAt(client.getClientSecretExpiresAt());
        dto.setClientSettings(client.getClientSettings());
        dto.setTokenSettings(client.getTokenSettings());
        return dto;
    }

    // エンティティ → クレデンシャルレスポンスDTO変換
    private Oauth2RegisteredClientCredentialsResponseDto toCredentialResponseDTO(Oauth2RegisteredClientEntity client) {
        Oauth2RegisteredClientCredentialsResponseDto dto = new Oauth2RegisteredClientCredentialsResponseDto();
        dto.setId(client.getId());
        dto.setClientId(client.getClientId());
        dto.setClientSecret(client.getClientSecret());
        dto.setClientIdIssuedAt(client.getClientIdIssuedAt());
        dto.setClientName(client.getClientName());
        dto.setClientAuthenticationMethods(List.of(client.getClientAuthenticationMethods().split(",")));
        dto.setAuthorizationGrantTypes(List.of(client.getAuthorizationGrantTypes().split(",")));
        dto.setScopes(List.of(client.getScopes().split(",")));
        dto.setRedirectUris(client.getRedirectUris() != null ? List.of(client.getRedirectUris().split(",")) : null);
        dto.setPostLogoutRedirectUris(client.getPostLogoutRedirectUris() != null ? List.of(client.getPostLogoutRedirectUris().split(",")) : null);
        dto.setClientSecretExpiresAt(client.getClientSecretExpiresAt());
        dto.setClientSettings(client.getClientSettings());
        dto.setTokenSettings(client.getTokenSettings());
        return dto;
    }
}
