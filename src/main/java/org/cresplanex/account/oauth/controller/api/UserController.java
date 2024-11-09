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
import org.springframework.web.bind.annotation.*;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

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

        response.setSuccess(true);
        response.setData(userResponseDto);
        response.setCode(AuthServerErrorCode.SUCCESS);
        response.setCaption("User created successfully.");

        return ResponseEntity.ok(response);
    }

    @RequestMapping(value = "/{userId}", method = RequestMethod.GET)
    public ResponseEntity<ResponseDto<UserResponseDto>> getUser(
            @PathVariable String userId
    ) {
        UserEntity userEntity = userService.findById(userId);
        UserResponseDto userResponseDto = toResponseDTO(userEntity);
        ResponseDto<UserResponseDto> response = new ResponseDto<>();

        response.setSuccess(true);
        response.setData(userResponseDto);
        response.setCode(AuthServerErrorCode.SUCCESS);
        response.setCaption("User found successfully.!");

        return ResponseEntity.ok(response);
    }

    @RequestMapping(method = RequestMethod.GET)
    public ResponseEntity<ResponseDto<List<UserResponseDto>>> getUserList(
    ) {
        List<UserEntity> userEntityList = userService.getList();
        List<UserResponseDto> userResponseDtoList = userEntityList.stream()
                .map(this::toResponseDTO)
                .collect(Collectors.toList());
        ResponseDto<List<UserResponseDto>> response = new ResponseDto<>();

        response.setSuccess(true);
        response.setData(userResponseDtoList);
        response.setCode(AuthServerErrorCode.SUCCESS);
        response.setCaption("User list found successfully.!");

        return ResponseEntity.ok(response);
    }

    // エンティティ → レスポンスDTO変換
    private UserResponseDto toResponseDTO(UserEntity user) {

        return new UserResponseDto(
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
    }
}
