package org.cresplanex.account.oauth.controller.api;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;
import org.cresplanex.account.oauth.dto.api.ResponseDto;
import org.cresplanex.account.oauth.dto.api.user.CreateUserRequestDto;
import org.cresplanex.account.oauth.dto.api.user.UserResponseDto;
import org.cresplanex.account.oauth.entity.AccountEntity;
import org.cresplanex.account.oauth.entity.UserEntity;
import org.cresplanex.account.oauth.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.time.format.DateTimeFormatter;

@RestController
@AllArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @RequestMapping(method = RequestMethod.POST)
    public ResponseEntity<ResponseDto<UserResponseDto>> createUser(
            @Valid @RequestBody CreateUserRequestDto dto
            ) {
        AccountEntity accountEntity = new AccountEntity();
        accountEntity.setLoginId(dto.getEmail());
        UserEntity userEntity = userService.create(
                accountEntity,
                dto.getPassword(),
                dto.getName(),
                dto.getEmail()
        );

        UserResponseDto userResponseDto = toResponseDTO(userEntity);
        ResponseDto<UserResponseDto> response = new ResponseDto<>();
        response.setData(userResponseDto);
        response.setCode(AuthServerErrorCode.SUCCESS);
        response.setCaption("User created successfully.");

        return ResponseEntity.ok(response);
    }

    // エンティティ → レスポンスDTO変換
    private UserResponseDto toResponseDTO(UserEntity user) {
        UserResponseDto dto = new UserResponseDto(
                user.getUserId(),
                user.getName(),
                user.getEmail(),
                user.getGivenName(),
                user.getFamilyName(),
                user.getMiddleName(),
                user.getNickname(),
                user.getPreferredUsername(),
                user.getAddress(),
                user.getProfile(),
                user.getPicture(),
                user.getWebsite(),
                user.getPhone(),
                user.getGender(),
                user.getBirthdate() == null ? null : user.getBirthdate().format(DateTimeFormatter.ISO_DATE),
                user.getZoneinfo(),
                user.getLocale()
        );

        return dto;
    }
}
