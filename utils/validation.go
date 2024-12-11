package validation

import (
    "errors"
    "fmt"
    "os"
    "regexp"
    "strconv"
)

func ValidateUsername(username string) error {
    if err := checkUsernameLength(username); err != nil {
        return err
    }
    return checkUsernameCharacters(username)
}

func checkUsernameLength(username string) error {
    if len(username) < 3 || len(username) > 30 {
        return errors.New("username must be between 3 and 30 characters long")
    }
    return nil
}

func checkUsernameCharacters(username string) error {
    match, err := regexp.MatchString("^[a-zA-Z0-9._]+$", username)
    if err != nil {
        return fmt.Errorf("failed to validate username characters: %w", err)
    }
    if !match {
        return errors.New("username can only contain alphanumeric characters, dots, or underscores")
    }
    return nil
}

func ValidatePassword(password string) error {
    minLength, maxLength := getPasswordConstraints()
    if len(password) < minLength || len(password) > maxLength {
        return errors.New("password length is out of the allowed range")
    }

    return checkPasswordStrength(password)
}

func getPasswordConstraints() (minLength, maxLength int) {
    var err error
    minLength, err = strconv.Atoi(os.Getenv("PASSWORD_MIN_LENGTH"))
    if err != nil {
        minLength = 8
    }
    maxLength, err = strconv.Atoi(os.Getenv("PASSWORD_MAX_LENGTH"))
    if err != nil {
        maxLength = 64
    }
    return minLength, maxLength
}

func ValidateEmail(email string) error {
    match, err := regexp.MatchString(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`, email)
    if err != nil {
        return fmt.Errorf("failed to validate email: %w", err)
    }
    if !match {
        return errors.New("invalid email format")
    }
    return nil
}

func ValidateMessageLength(message string) error {
    maxMessageLength := getMessageMaxLength()
    if len(message) > maxMessageLength {
        return errors.New("message exceeds the maximum allowed length")
    }
    return nil
}

func getMessageMaxLength() int {
    maxMessageLength, err := strconv.Atoi(os.Getenv("MESSAGE_MAX_LENGTH"))
    if err != nil {
        maxMessageLength = 1000
    }
    return maxMessageLength
}

func checkPasswordStrength(password string) error {
    var (
        hasUppercase   = regexp.MustCompile(`[A-Z]`)
        hasLowercase   = regexp.MustCompile(`[a-z]`)
        hasDigit       = regexp.MustCompile(`[0-9]`)
        hasSpecialChar = regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>/\?~]`)
    )

    if !hasUppercase.MatchString(password) {
        return errors.New("password must include at least one uppercase character")
    }
    if !hasLowercase.MatchString(password) {
        return errors.New("password must include at least one lowercase character")
    }
    if !hasDigit.MatchString(password) {
        return errors.New("password must contain at least one digit")
    }
    if !hasSpecialChar.MatchString(password) {
        return errors.New("password must contain at least one special character")
    }

    return nil
}