package org.cresplanex.account.oauth.service;

import lombok.AllArgsConstructor;
import org.cresplanex.account.oauth.entity.Oauth2RegisteredClientEntity;
import org.cresplanex.account.oauth.repository.Oauth2RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class Oauth2RegisteredClientService {

    private final Oauth2RegisteredClientRepository repository;

    public Oauth2RegisteredClientEntity createClient(Oauth2RegisteredClientEntity client) {
        return repository.save(client);
    }

    public Optional<Oauth2RegisteredClientEntity> getClientById(String id) {
        return repository.findById(id);
    }

    public Optional<Oauth2RegisteredClientEntity> getClientByClientId(String clientId) {
        return repository.findByClientId(clientId);
    }

    public List<Oauth2RegisteredClientEntity> getAllClients() {
        return repository.findAll();
    }

    public Oauth2RegisteredClientEntity updateClient(String id, Oauth2RegisteredClientEntity updatedClient) {
        return repository.findById(id)
                .map(client -> {
                    client.setClientName(updatedClient.getClientName());
                    client.setRedirectUris(updatedClient.getRedirectUris());
                    client.setScopes(updatedClient.getScopes());
                    client.setClientAuthenticationMethods(updatedClient.getClientAuthenticationMethods());
                    client.setAuthorizationGrantTypes(updatedClient.getAuthorizationGrantTypes());
                    client.setClientSettings(updatedClient.getClientSettings());
                    client.setTokenSettings(updatedClient.getTokenSettings());
                    return repository.save(client);
                }).orElseThrow(() -> new RuntimeException("Client not found: " + id));
    }

    public void deleteClient(String id) {
        if (repository.existsById(id)) {
            repository.deleteById(id);
        } else {
            throw new RuntimeException("Client not found: " + id);
        }
    }
}
