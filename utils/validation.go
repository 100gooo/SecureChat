package validation

import (
    "errors"
    "os"
    "regexp"
    "strconv"
)

func ValidateUsername(username string) error {
    if err := validateUsernameLength(username); err != nil {
        return err
    }
    if err := validateUsernameCharacters(username); err != nil {
        return err
    }
    return nil
}

func validateUsernameLength(username string) error {
    if len(username) < 3 || len(username) > 30 {
        return errors.New("username must be between 3 and 30 characters long")
    }
    return nil
}

func validateUsernameCharacters(username string) error {
    if match, _ := regexp.MatchString("^[a-zA-Z0-9._]+$", username); !match {
        return errors.New("username can only contain alphanumeric characters, dots, or underscores")
    }
    return nil
}

func ValidatePassword(password string) error {
    minLength, maxLength := getPasswordLengthConstraints()
    if len(password) < minLength || len(password) > maxLength {
        return errors.New("password length is out of the allowed range")
    }

    if err := checkPasswordStrength(password); err != nil {
        return err
    }

    return nil
}

func getPasswordLengthConstraints() (minLength, maxLength int) {
    minLength, _ = strconv.Atoi(os.Getenv("PASSWORD_MIN_LENGTH"))
    maxLength, _ = strconv.Atoi(os.Getenv("PASSWORD_MAX_LENGTH"))
    return minLength, maxLength
}

func ValidateEmail(email string) error {
    if match, _ := regexp.MatchString(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`, email); !match {
        return errors.New("invalid email format")
    }
    return nil
}

func ValidateMessageLength(message string) error {
    maxLength := getMessageMaxLength()
    if len(message) > maxLength {
        return errors.New("message exceeds the maximum allowed length")
    }
    return nil
}

func getMessageMaxLength() int {
    maxLength, _ := strconv.Atoi(os.Getenv("MESSAGE_MAX_LENGTH"))
    return maxLength
}

func checkPasswordStrength(password string) error {
    var (
        hasUpper   = regexp.MustCompile(`[A-Z]`)
        hasLower   = regexp.MustCompile(`[a-z]`)
        hasNumber  = regexp.MustCompile(`[0-9]`)
        hasSpecial = regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>/\?~]`)
    )

    if !hasUpper.MatchString(password) {
        return errors.New("password must include at least one uppercase character")
    }
    if !hasLower.MatchString(password) {
        return errors.New("password must include at least one lowercase character")
    }
    if !hasNumber.MatchString(password) {
        return errors.New("password must contain at least one digit")
    }
    if !hasSpecial.MatchString(password) {
        return errors.New("password must contain at least one special character")
    }

    return nil
}