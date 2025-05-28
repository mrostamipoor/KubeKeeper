package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "log"
    "os"
    "os/exec"
    "encoding/hex"
    "path/filepath"
    //zerolog "github.com/rs/zerolog/log"
    "regexp"
    "strconv"
)

func init() {
    log.SetOutput(os.Stderr)
    log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func decryptAESGCM(encryptedData, key []byte) ([]byte, error) {
    if len(encryptedData) < 12 {
        log.Println("Encrypted data is too short.")
        return nil, fmt.Errorf("invalid encrypted data length")
    }

    nonce := encryptedData[:12]
    ciphertext := encryptedData[12:]
    block, err := aes.NewCipher(key)
    if err != nil {
        log.Printf("Failed to create cipher block: %v\n", err)
        return nil, err
    }
    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Printf("Failed to create GCM: %v\n", err)
        return nil, err
    }
    decryptedData, err := aesgcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, err
    }
        
    return decryptedData, nil
}

func executeLs(path string) {
    cmd := exec.Command("ls", "-l", path)
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to execute ls on %s: %v\n", path, err)
    } else {
        log.Printf("ls -l output for %s:\n%s\n", path, output)
    }
}
func processSecrets() error {
    // Retrieve all secret directories
    dirs, err := ioutil.ReadDir("/etc/")
    if err != nil {
        log.Printf("Failed to read directory /etc/: %v", err)
        return err
    }

    var indices []int
    secretDirPattern := regexp.MustCompile(`encrypted-secret(\d+)`)
    for _, dir := range dirs {
        if matches := secretDirPattern.FindStringSubmatch(dir.Name()); matches != nil {
            index, err := strconv.Atoi(matches[1])
            if err != nil {
                log.Printf("Failed to parse index from directory name %s: %v", dir.Name(), err)
                continue
            }
            indices = append(indices, index)
        }
    }

    for _, i := range indices {
        err := processSecretDirectory(i)
        if err != nil {
            log.Printf("Failed to process secret directory encrypted-secret%d: %v", i, err)
            return err
        }
    }

    return nil
}

func processSecretDirectory(i int) error {
    //for i := 1; ; i++ {
        secretPath := fmt.Sprintf("/etc/encrypted-secret%d/", i)
        executeLs(secretPath)

        envVarName := fmt.Sprintf("ENCRYPTION_KEY_%d", i)
        keyData := os.Getenv(envVarName)
        if keyData == "" {
            log.Printf("Encryption key not found for %s. Stopping process.", secretPath)
            return nil
        }

        key, err := base64.StdEncoding.DecodeString(keyData)
        if err != nil {
            log.Printf("Failed to decode key: %v", err)
            return err
        }

        hexKey := "62f1c362c106c3731616adb09163159de380e0d4baf2b306beae57b73c4dfb32"
        encKey, err := hex.DecodeString(hexKey)
        if err != nil {
            log.Printf("Failed to decode hex key: %v", err)
            return err
        }

        decryptedKey, err := decryptAESGCM(key, encKey)
        if err != nil {
            log.Printf("Failed to decrypt key: %v", err)
            return err
        }

        files, err := ioutil.ReadDir(secretPath)
        if err != nil {
            log.Printf("Failed to read directory %s: %v", secretPath, err)
            return err
        }

        var validFileNames = map[string]bool{"token": true, "namespace": true, "ca.crt": true}

        var filePaths []string
        for _, fileInfo := range files {
            if validFileNames[fileInfo.Name()] {
                filePaths = append(filePaths, fileInfo.Name())
            }
        }
        log.Printf("Valid filePaths: %v", filePaths)
        
        var decryptFiles = true
        expectedFiles := []string{"token", "namespace", "ca.crt"}
        if len(filePaths) == len(expectedFiles) {
            for _, file := range expectedFiles {
                if !contains(filePaths, file) {
                    decryptFiles = false
                    break
                }
            }
        } else {
            decryptFiles = false
        }

        for _, fileInfo := range files {
            fullPath := filepath.Join(secretPath, fileInfo.Name())
            resolvedPath, err := filepath.EvalSymlinks(fullPath)
            if err != nil {
                log.Printf("Failed to resolve symlink %s: %v", fullPath, err)
                return err
            }
        
            resolvedFileInfo, err := os.Stat(resolvedPath)
            if err != nil {
                log.Printf("Failed to stat resolved path %s: %v", resolvedPath, err)
                return err
            }
        
            if resolvedFileInfo.IsDir() {
                log.Printf("Skipping directory %s", resolvedPath)
                continue
            }
        
            if !resolvedFileInfo.Mode().IsRegular() {
                log.Printf("Skipping non-regular file %s", resolvedPath)
                continue
            }
        
            if decryptFiles && (fileInfo.Name() == "ca.crt" || fileInfo.Name() == "namespace") {
                log.Printf("Copying non-decryptable file %s", fileInfo.Name())
                data, err := ioutil.ReadFile(resolvedPath)
                if err != nil {
                    log.Printf("Failed to read file %s: %v", resolvedPath, err)
                    return err
                }
                outputPath := fmt.Sprintf("/etc/secret%d/%s", i, fileInfo.Name())
                if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
                    log.Printf("Failed to copy file %s to %s: %v", fileInfo.Name(), outputPath, err)
                    return err
                }
                continue
            }
        
            // Decrypt other files
            log.Printf("Decrypting file %s", fileInfo.Name())
            data, err := ioutil.ReadFile(resolvedPath)
            if err != nil {
                log.Printf("Failed to read file %s: %v", resolvedPath, err)
                return err
            }
        
            decodedData, err := base64.StdEncoding.DecodeString(string(data))
            if err != nil {
                log.Printf("Failed to decode base64 data, using raw data: %v", err)
                decodedData = data // Only continue with raw data if it's certain it should be non-base64.
            }
        
            decryptedData, err := decryptAESGCM(decodedData, decryptedKey)
            if err != nil {
                log.Printf("Failed to decrypt data: %v", err)
                return err
            }
        
            outputPath := fmt.Sprintf("/etc/secret%d/%s", i, fileInfo.Name())
            err = ioutil.WriteFile(outputPath, decryptedData, 0644)
            if err != nil {
                log.Printf("Failed to write decrypted data to %s: %v", outputPath, err)
                return err
            }
        }
    ///}
    return nil
}

func contains(slice []string, str string) bool {
    for _, v := range slice {
        if v == str {
            return true
        }
    }
    return false
}


func main() {
    if err := processSecrets(); err != nil {
        log.Fatalf("Error processing secrets: %v\n", err)
    }
    log.Println("Successfully processed all secrets.")
}
