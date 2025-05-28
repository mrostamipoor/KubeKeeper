package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "encoding/hex"
    corev1 "k8s.io/api/core/v1"
    "github.com/rs/zerolog/log"
    admission "k8s.io/api/admission/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    //appv1 "k8s.io/api/apps/v1" // For Deployments
    "k8s.io/apimachinery/pkg/runtime"
    "k8s.io/apimachinery/pkg/runtime/serializer"
    "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    bolt "go.etcd.io/bbolt"
    "encoding/base64"
    "strings"
    "io/ioutil"
    "sigs.k8s.io/yaml" 
    originallog "log"
)
var db *bolt.DB
var (
    runtimeScheme = runtime.NewScheme()
    codecFactory  = serializer.NewCodecFactory(runtimeScheme)
    deserializer  = codecFactory.UniversalDeserializer()
   )
func initDB() error {
    var err error
    db, err = bolt.Open("secret.db", 0600, nil)
    if err != nil {
        return err
    }
    return db.Update(func(tx *bolt.Tx) error {
        _, err := tx.CreateBucketIfNotExists([]byte("Secrets"))
        return err
    })
}
// Function to print all entries in the database
func printDB() {
    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        if b == nil {
            return fmt.Errorf("Secrets bucket does not exist")
        }
        return b.ForEach(func(k, v []byte) error {
            fmt.Printf("Key: %s, Value: %s\n", k, v)
            return nil
        })
    })
    if err != nil {
        log.Error().Err(err).Msg("Error reading from database")
    }
}
func init() {
    _ = admission.AddToScheme(runtimeScheme)
}

func serve(w http.ResponseWriter, r *http.Request, admitFunc func(admission.AdmissionReview) *admission.AdmissionResponse) {
    log.Info().Msg("server function has been called.")
    if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
        http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
        return
    }
    defer r.Body.Close()
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read request body", http.StatusInternalServerError)
        return
    }

    var admissionReview admission.AdmissionReview
    if _, _, err := deserializer.Decode(body, nil, &admissionReview); err != nil {
        http.Error(w, fmt.Sprintf("Request could not be decoded: %s", err), http.StatusBadRequest)
        return
    }

    response := admitFunc(admissionReview)
    respAdmissionReview := admission.AdmissionReview{
        Response: response,
    }

    respAdmissionReview.APIVersion = "admission.k8s.io/v1"
    respAdmissionReview.Kind = "AdmissionReview"
    respAdmissionReview.Response.UID = admissionReview.Request.UID

    respBytes, err := json.Marshal(respAdmissionReview)
    if err != nil {
        http.Error(w, fmt.Sprintf("Failed to encode response: %s", err), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    w.Write(respBytes)
}

func secretMutation(ar admission.AdmissionReview) *admission.AdmissionResponse {
    var secret corev1.Secret
    if err := json.Unmarshal(ar.Request.Object.Raw, &secret); err != nil {
        log.Error().Err(err).Msg("Could not unmarshal raw object")
        return &admission.AdmissionResponse{
            Allowed: false,
            Result: &metav1.Status{
                Message: err.Error(),
            },
        }
    }
    secretYAML, err1 := yaml.Marshal(secret)
    if err1 != nil {
        originallog.Println("Failed to marshal secret to YAML:", err1)
        return &admission.AdmissionResponse{
            Allowed: false,
            Result: &metav1.Status{
                Message: err1.Error(),
            },
        }
    }
    
    // Log the entire Secret in YAML format
    originallog.Println("Received Secret:")
    originallog.Println(string(secretYAML))
    // Check and print the content of the data section of the secret
    if len(secret.Data) > 0 {
        //log.Info().Msg("Secret Data Found:")
        for key, value := range secret.Data {
            decodedValue := string(value) 
            log.Info().Strs("data", []string{key}).Strs("value", []string{decodedValue}).Msg("Secret data content")
        }
    } else {
        //log.Info().Msg("No data available in the Secret.")
        return &admission.AdmissionResponse{
            Allowed: true,
        }
    }
    var patchOps []map[string]interface{}

    // Check for last-applied-configuration annotation and prepare to remove it
    if _, ok := secret.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
        removeOp := map[string]interface{}{
            "op":   "remove",
            "path": "/metadata/annotations/kubectl.kubernetes.io~1last-applied-configuration",
        }
        patchOps = append(patchOps, removeOp)
    }
    // Check if the secret is a service account token
    //---------------------------------------------------
    if secret.Type == corev1.SecretTypeServiceAccountToken {
        var encryptionKey []byte
        var err error

        serviceAccountName, notError := secret.ObjectMeta.Annotations["kubernetes.io/service-account.name"]        
        if !notError {
            //log.Info().Msg("No service account name found, returning without storing key")
            return &admission.AdmissionResponse{
                Allowed: false,
                Result: &metav1.Status{
                    Message: err.Error(),
                },
            }
        }  

        encryptionKey, err = fetchKey(secret.Namespace, serviceAccountName)
        if err != nil {
            encryptionKey, err = generateKey() // Generate a new key for each new Secret
            if err != nil {
                log.Error().Err(err).Msg("Failed to generate key")
                return &admission.AdmissionResponse{
                    Allowed: false,
                    Result: &metav1.Status{
                        Message: err.Error(),
                    },
                }
            }
            //log.Info().Interface("encryptionKey", encryptionKey).Msg("encryptionKey to be stored in DB")
            // Store or update the encryption key or labels
            ownershipValue, ok := secret.ObjectMeta.Annotations["secret-ownership"]        
            if !ok {
                log.Info().Msg("No 'secret-ownership' annotation found, returning without storing key")
                return &admission.AdmissionResponse{
                    Allowed: false,
                    Result: &metav1.Status{
                        Message: err.Error(),
                    },
                }
            }
            //log.Printf("AES Key %v\n", encryptionKey)
            log.Info().Interface("AES Key", encryptionKey).Msg("Generated AES encryption key")
            storeKey(secret.Namespace, secret.Name, encryptionKey, ownershipValue,serviceAccountName)
    
            newSecretData := make(map[string][]byte)
    
            for dataKey, dataValue := range secret.Data {
                if dataKey == "token" { // Encrypt only the token
                    log.Printf("token is encrypting...")
                    encryptedValue, err := encryptAESGCM(dataValue, encryptionKey)
                    //log.Printf("dataValue %v\n", dataValue)
                    log.Info().Interface("dataValue", dataValue).Msg("recieved dataValue")
                    //log.Printf("encryptedValue %v\n", encryptedValue)
                    log.Info().Interface("AES encryptedValue", encryptedValue).Msg("Generated encryptedValue")
                    if err != nil {
                        originallog.Println("Error encrypting secret token:", err)
                        return &admission.AdmissionResponse{
                            Allowed: false,
                            Result: &metav1.Status{
                                Message: err.Error(),
                            },
                        }
                    }
                    tmpValue := base64.StdEncoding.EncodeToString(encryptedValue)
                    log.Printf("base encoded value %v\n", tmpValue)
                    encodedValue := []byte(tmpValue)
                    newSecretData[dataKey] = encodedValue
                    
                } else {
                    // Directly assign other data without encryption
                    newSecretData[dataKey] = dataValue
                }
            }
            log.Info().Interface("newSecretData", newSecretData).Msg("newSecretData")
            // Create a JSON Patch to update the secret data
            replaceOp := map[string]interface{}{
                "op":    "replace",
                "path":  "/data",
                "value": newSecretData,
            }
            patchOps = append(patchOps, replaceOp)
            patchBytes, err := json.Marshal(patchOps)
            if err != nil {
                log.Error().Err(err).Msg("Could not marshal JSON patch")
                return &admission.AdmissionResponse{
                    Allowed: false,
                    Result: &metav1.Status{
                        Message: err.Error(),
                    },
                }
            }
            printDB()
            return &admission.AdmissionResponse{
                Allowed: true,
                Patch:   patchBytes,
                PatchType: func() *admission.PatchType {
                    pt := admission.PatchTypeJSONPatch
                    return &pt
                }(),
            }
        } else {
            return &admission.AdmissionResponse{
                Allowed: true,
            }            
        }

//else else else else else else else else else else else else     
    } else {
        var encryptionKey []byte
        var err error
        isNewSecret := ar.Request.Operation == "CREATE"
        log.Info().Strs("isNewSecret", []string{fmt.Sprintf("%v", isNewSecret)}).Msg("isNewSecret")
    
        if isNewSecret {
            log.Info().Msg("is New Secret")
            encryptionKey, err = generateKey() // Generate a new key for each new Secret
            if err != nil {
                log.Error().Err(err).Msg("Failed to generate key")
                return &admission.AdmissionResponse{
                    Allowed: false,
                    Result: &metav1.Status{
                        Message: err.Error(),
                    },
                }
            }
        } else {
            log.Info().Msg("is not New Secret")
            return &admission.AdmissionResponse{
                Allowed: true,
            }
            // Fetch the existing encryption key from the database
            encryptionKey, err = fetchKey(secret.Namespace, secret.Name)
            if err != nil {
                log.Error().Err(err).Msg("Failed to fetch encryption key")
                return &admission.AdmissionResponse{
                    Allowed: false,
                    Result: &metav1.Status{
                        Message: err.Error(),
                    },
                }
            }
        }
        log.Info().Interface("encryptionKey", encryptionKey).Msg("encryptionKey to be stored in DB")
        // Store or update the encryption key or labels
        ownershipValue, ok := secret.ObjectMeta.Annotations["secret-ownership"]        
        if ok {
            storeKey(secret.Namespace, secret.Name, encryptionKey, ownershipValue,"")
            } else {
            log.Info().Msg("No 'secret-ownership' annotation found, proceeding without storing key")
            return &admission.AdmissionResponse{
                Allowed: false,
                Result: &metav1.Status{
                    Message: err.Error(),
                },
            }
        }
    
        newSecretData := make(map[string][]byte)
        for dataKey, dataValue := range secret.Data {
            encryptedValue, err := encryptAESGCM(dataValue, encryptionKey)
            if err != nil {
                log.Error().Err(err).Msg("Error encrypting secret data")
                return &admission.AdmissionResponse{
                    Allowed: false,
                    Result: &metav1.Status{
                        Message: err.Error(),
                    },
                }
            }
            newSecretData[dataKey] = encryptedValue
        }
    
        log.Info().Interface("newSecretData", newSecretData).Msg("newSecretData to be stored in object")
    
        // Create a JSON Patch to update the secret data
        replaceOp := map[string]interface{}{
            "op":    "replace",
            "path":  "/data",
            "value": newSecretData,
        }
        patchOps = append(patchOps, replaceOp)
        patchBytes, err := json.Marshal(patchOps)
        if err != nil {
            log.Error().Err(err).Msg("Could not marshal JSON patch")
            return &admission.AdmissionResponse{
                Allowed: false,
                Result: &metav1.Status{
                    Message: err.Error(),
                },
            }
        }
        printDB()
        return &admission.AdmissionResponse{
            Allowed: true,
            Patch:   patchBytes,
            PatchType: func() *admission.PatchType {
                pt := admission.PatchTypeJSONPatch
                return &pt
            }(),
        }
    }


}


// Fetches the encryption key from the database
func fetchKey(namespace, secretName string) ([]byte, error) {
    dbKey := secretName + ":" + namespace
    var jsonData map[string]interface{}

    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        if b == nil {
            return fmt.Errorf("Secrets bucket does not exist")
        }
        v := b.Get([]byte(dbKey))
        if v == nil {
            return fmt.Errorf("Key not found in database")
        }
        return json.Unmarshal(v, &jsonData)
    })

    if err != nil {
        log.Error().Err(err).Msg("Error retrieving data from database")
        return nil, err
    }

    encKeyStr := jsonData["encKey"].(string)
    return base64.StdEncoding.DecodeString(encKeyStr)
}

func storeKey(namespace, secretName string, encKey []byte, ownership, serviceAccountName string) {
    // Concatenate secretName and namespace to form the key
    dbKey := secretName + ":" + namespace
    // Encode the encryption key in base64 for storage
    encodedKey := base64.StdEncoding.EncodeToString(encKey)
    
    // Split the ownership string by ';', even if it does not contain ';'
    ownershipList := strings.Split(ownership, ";")

    // Log the result of the split for debugging
    //originallog.Println("Ownership split result:", ownershipList)

    // Create the JSON object
    // Include serviceAccountName if it's provided
    var value map[string]interface{}
    if serviceAccountName == "" {
        value = map[string]interface{}{
            "encKey":            encodedKey,
            "ownership":        ownershipList,
        }
    } else {
        value = map[string]interface{}{            
            "encKey":            encodedKey,
            "ownership":        ownershipList,
            "serviceAccountName":        serviceAccountName,
        }
    }


    // Marshal the JSON data
    jsonData, err := json.Marshal(value)
    if err != nil {
        originallog.Println("Error marshaling JSON data:", err)
        return
    }

    // Store the data in the database using the dbKey as a string
    err = db.Update(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        if b == nil {
            return fmt.Errorf("Secrets bucket does not exist")
        }
        return b.Put([]byte(dbKey), jsonData)
    })

    if err != nil {
        originallog.Println("Error storing data in database:", err)
    }
}
// Generate a new AES key
func generateKey() ([]byte, error) {
    key := make([]byte, 32) // AES-256
    if _, err := rand.Read(key); err != nil {
        return nil, err
    }
    return key, nil
}

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, 12) // 12 bytes for GCM standard nonce size
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
    // Combine the nonce with the ciphertext for easier management
    return append(nonce, ciphertext...), nil
}
func decryptAESGCM(encryptedData []byte, key []byte) (string, error) {
    // Assuming the nonce is the first 12 bytes of the encrypted data
    nonce := encryptedData[:12]
    ciphertext := encryptedData[12:]

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), err
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
type Config struct {
    BlockedAccounts []struct {
        Namespace      string `json:"namespace"`
        ServiceAccount string `json:"serviceAccount"`
    } `json:"blockedAccounts"`
}

func loadConfig(path string) Config {
    file, err := ioutil.ReadFile(path)
    if err != nil {
        log.Error().Err(err).Msg("Unable to read config file")
    }
    var config Config
    err = json.Unmarshal(file, &config)
    if err != nil {
        log.Error().Err(err).Msg("Unable to parse config JSON")
    }
    return config
}
func extractServiceAccountName(ar admission.AdmissionReview) (string, error) {
    var pod corev1.Pod
    if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
        return "", fmt.Errorf("error unmarshalling Pod object: %v", err)
    }
    return pod.Spec.ServiceAccountName, nil
}

func deploymentMutation(ar admission.AdmissionReview) *admission.AdmissionResponse {
    // Main mutate function to orchestrate mutation steps
    config := loadConfig("/etc/config/config.json")
    namespace := ar.Request.Namespace
    //log.Printf("namespace: %s", namespace)

    userInfo := ar.Request.UserInfo
    requestServiceAccount := userInfo.Username
    // Optionally, parse the serviceAccount to extract just the name
    // Expected format: "system:serviceaccount:[namespace]:[service account name]"
    parts := strings.Split(requestServiceAccount, ":")
    if len(parts) == 4 {
        requestServiceAccount = parts[3] // This is the actual service account name
    }

    //log.Printf("Received request from Namespace: %s, Service Account: %s", namespace, serviceAccount)

    // Extract the service account name using the new function
    objectServiceAccount, err := extractServiceAccountName(ar)
    if err != nil {
        return &admission.AdmissionResponse{
            Result: &metav1.Status{
                Message: fmt.Sprintf("Error extracting service account name: %v", err),
            },
        }
    }

    //log.Printf("%s is using Service Account Name: %s", ar.Request.Kind.Kind, serviceAccountName)

    var pod corev1.Pod
    if err := json.Unmarshal(ar.Request.Object.Raw, &pod); err != nil {
        originallog.Println("Could not unmarshal raw Pod object:", err)
        return &admission.AdmissionResponse{
            Allowed: false,
            Result: &metav1.Status{
                Message: err.Error(),
            },
        }
    }

    // Serialize the Pod object into YAML format
    /*podYAML, err := yaml.Marshal(pod)
    if err != nil {
        originallog.Println("Failed to marshal pod to YAML:", err)
        return &admission.AdmissionResponse{
            Allowed: false,
            Result: &metav1.Status{
                Message: err.Error(),
            },
        }
    }*/
    
    // Log the entire Pod in YAML format
    //originallog.Println("Received Pod:")
    //originallog.Println(string(podYAML))
    
    for _, account := range config.BlockedAccounts {
        if namespace == account.Namespace && requestServiceAccount == account.ServiceAccount {
            return &admission.AdmissionResponse{
                Allowed: false,
                Result: &metav1.Status{
                    Message: "Requests from this service account are not allowed.",
                },
            }
        }
    }
    // Extract the necessary attributes
    checkOwnerRef := false
    resourceName := ar.Request.Name
    if resourceName == "" {
        resourceName = pod.GenerateName // Using GenerateName if Name is not provided
        checkOwnerRef = true
    }
    // Extract and log the owner reference 'kind'
    var kind string
    if checkOwnerRef {
        if len(pod.ObjectMeta.OwnerReferences) > 0 {
         // Check ownerReferences for controller true and extract 'kind'
        hasController := false
        for _, owner := range pod.ObjectMeta.OwnerReferences {
            if owner.Controller != nil && *owner.Controller {
                originallog.Printf("Controller Owner Kind: %s\n", owner.Kind)
                if owner.Kind == "ReplicaSet" {
                    kind = "Deployment"
                } else {
                    kind=owner.Kind
                }

                hasController = true
            }
        }
        if !hasController {
            originallog.Println("No controller owner references found in this Pod.")
        }

        } else {
            originallog.Println("No owner references found in this Pod.")
            kind = ""
        } 
    } else {
        kind = ar.Request.Kind.Kind
    } 
    
    
    // Construct the unique identifier
    resourceIdentifier := fmt.Sprintf("%s:%s:%s", resourceName, kind, namespace)

    log.Info().Str("resourceIdentifier",resourceIdentifier).Msg("resourceIdentifier")
    obj, err := handleAdmissionRequest(ar)
    if err != nil {
        return &admission.AdmissionResponse{
            Result: &metav1.Status{
                Message: fmt.Sprintf("Could not unmarshal raw object: %v", err),
            },
        }
    }

    sensitiveVolumes, found, valid := extractVolumes(obj, resourceIdentifier, objectServiceAccount)
    if !found {
        return &admission.AdmissionResponse{
            Allowed: true,
        }
    }
    if !valid {
        return &admission.AdmissionResponse{
            Allowed: false,
            Result: &metav1.Status{
                Message: "Access denied due to ownership restrictions or invalid resource identifiers for one or more secrets.",
            },
        }
    }
    originallog.Println("valid!")
    patches := make([]map[string]interface{}, 0)
    //volumeIndex := 0
    //--------------------------------------------- HERE
    for _, volume := range sensitiveVolumes {
        volumeIndex, ok := volume["index"].(int) 
        if !ok {
            originallog.Println("Invalid volume index")
            continue
        }
        //if _, ok := volume["secret"]; ok {
            // Handling secret volumes (existing logic)
            originallog.Println("secret!")
            secretVolumePatch := map[string]interface{}{
                "op":    "replace",
                "path":  fmt.Sprintf("/spec/volumes/%d/name", volumeIndex),
                "value": fmt.Sprintf("encrypted-%s", volume["name"].(string)),
            }
    
            addEmptyDirPatch := map[string]interface{}{
                "op":   "add",
                "path": fmt.Sprintf("/spec/volumes/-"),
                "value": map[string]interface{}{
                    "name":     volume["name"].(string),
                    "emptyDir": map[string]interface{}{"medium": "Memory"},
                },
            }
    
            patches = append(patches, secretVolumePatch, addEmptyDirPatch)
            
        /*} else if tokenMap, ok := volume["serviceAccountToken"].(map[string]interface{}); ok {
            
            // Handling service account token volumes
            originalPath := tokenMap["path"].(string)
            originallog.Println("serviceAccountToken!")

            // Patch to rename the service account token volume path
            saTokenPathPatch := map[string]interface{}{
                "op":    "replace",
                "path":  fmt.Sprintf("/spec/volumes/%d/name", volumeIndex),
                "value": fmt.Sprintf("encrypted-%s", volume["name"].(string)),
            }
            originallog.Println("serviceAccountToken!")
            // Patch to add an emptyDir volume with the original path
            addEmptyDirPathPatch := map[string]interface{}{
                "op":   "add",
                "path": fmt.Sprintf("/spec/volumes/-"),
                "value": map[string]interface{}{
                    "name":     originalPath, // Use original path as name to avoid conflicts
                    "emptyDir": map[string]interface{}{"medium": "Memory"},
                },
            }
    
            patches = append(patches, saTokenPathPatch, addEmptyDirPathPatch)
        }*/
        
    }

    initContainer := setupInitContainer(sensitiveVolumes, namespace, objectServiceAccount)
    originallog.Println("setupInitContainer!")
    // We don't need it right now
    // sidecarContainer := setupSidecarContainer(secretsUsed, namespace)
    
    // Check if initContainers already exists
    var foundInit bool
    _, foundInit, err = unstructured.NestedFieldNoCopy(obj.Object, "spec", "template", "spec", "initContainers")
    if err != nil {
        log.Printf("Error checking for existing initContainers: %v", err)
    }

    var patch map[string]interface{}
    if foundInit {
        // Append to existing initContainers
        patch = map[string]interface{}{
            "op":    "add",
            "path":  "/spec/initContainers/-",
            "value": initContainer,
        }
    } else {
        // Add initContainers array with the first element
        patch = map[string]interface{}{
            "op":    "add",
            "path":  "/spec/initContainers",
            "value": []interface{}{initContainer}, // Ensure this is an array
        }
    }

    patches = append(patches, patch)
    
    // We don't need it right now
    // Patch for adding sidecar container
    /*patches = append(patches, map[string]interface{}{
        "op":    "add",
        "path":  "/spec/template/spec/containers/-",
        "value": sidecarContainer,
    })*/
    patchBytes, err := json.Marshal(patches)
    if err != nil {
        return &admission.AdmissionResponse{
            Result: &metav1.Status{
                Message: fmt.Sprintf("Error creating JSON patch: %v", err),
            },
        }
    }
    return &admission.AdmissionResponse{
        Allowed:   true,
        PatchType: func() *admission.PatchType { pt := admission.PatchTypeJSONPatch; return &pt }(),
        Patch:     patchBytes,
    }
}
func handleAdmissionRequest(ar admission.AdmissionReview) (obj *unstructured.Unstructured, err error) {
    // Unmarshal the raw object and handle errors
    obj = &unstructured.Unstructured{}
    err = json.Unmarshal(ar.Request.Object.Raw, obj)
    if err != nil {
        log.Error().Err(err).Msg("Could not unmarshal raw object.")
    }
    return
}
func extractVolumeDetails(ar admission.AdmissionReview) (obj *unstructured.Unstructured, err error) {
    // Unmarshal the raw object and handle errors
    obj = &unstructured.Unstructured{}
    err = json.Unmarshal(ar.Request.Object.Raw, obj)
    if err != nil {
        log.Error().Err(err).Msg("Could not unmarshal raw object.")
    }
    return
}
// checkOwnership fetches the ownership details from the DB and checks if the resourceIdentifier is allowed access
func checkOwnership(secretName, namespace, resourceIdentifier string, serviceAccount string) (bool, error) {
    var dbKey string
    dbKey = fmt.Sprintf("%s:%s", secretName, namespace)

    log.Info().Str("dbKey", dbKey).Msg("dbKey")
    var secretData map[string]interface{}

    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        if b == nil {
            return fmt.Errorf("Secrets bucket does not exist")
        }
        value := b.Get([]byte(dbKey))
        if value == nil {
            return fmt.Errorf("No data for key %s", dbKey)
        }
        return json.Unmarshal(value, &secretData)
    })

    if err != nil {
        return false, err
    }
    log.Info().Str("resourceIdentifier", resourceIdentifier).Msg("resourceIdentifier")
    // Check if the ownership field exists and contains the resourceIdentifier
	if ownershipList, exists := secretData["ownership"].([]interface{}); exists {
		for _, owner := range ownershipList {
			ownerString, ok := owner.(string)
			if ok {
				// Split both identifiers into parts
				ownerParts := strings.Split(ownerString, ":")
				resourceParts := strings.Split(resourceIdentifier, ":")

				// Check if we have exactly three parts for both identifiers
				if len(ownerParts) == 3 && len(resourceParts) == 3 {
					// Check if resourceName of ownerString is a prefix of resourceName of resourceIdentifier
					if strings.HasPrefix(resourceParts[0], ownerParts[0]) &&
						ownerParts[1] == resourceParts[1] && // Kind must be equal
						ownerParts[2] == resourceParts[2] { // Namespace must be equal
						return true, nil // Allowed access
					}
				}
			}
		}
	}
    return false, nil // Not allowed access
}
func extractVolumes(obj *unstructured.Unstructured, resourceIdentifier string, serviceAccount string) (sensitiveVolumes []map[string]interface{}, found bool, valid bool) {
    volumePath := []string{"spec", "volumes"} 
    valid = true
    volumes, found, _ := unstructured.NestedSlice(obj.Object, volumePath...) // Correct use of the spread operator
    if !found {
        return nil, false, true
    }

    for i, volume := range volumes {
        volMap, ok := volume.(map[string]interface{})
        if !ok {
            continue
        }
        if name, ok := volMap["name"].(string); ok && strings.HasPrefix(name, "kube-api-access-") {
            log.Info().Str("volumeName", name).Msg("Skipping auto-injected service account token volume based on name")
            continue  // Skip this volume
        }
        // Extract secret volumes
        if secretMap, ok := volMap["secret"].(map[string]interface{}); ok {
            if secretName, ok := secretMap["secretName"].(string); ok {
                allowed, err := checkOwnership(secretName, obj.GetNamespace(), resourceIdentifier, serviceAccount)
                if err != nil {
                    log.Error().Err(err).Msg("Failed to check ownership")
                    valid = false
                    continue
                }
                if !allowed {
                    valid = false
                    continue
                }
                sensitiveVolumes = append(sensitiveVolumes, map[string]interface{}{
                    "name":   volMap["name"],
                    "secret": secretName,
                    "index":  i, // Include the index of the volume
                })
            }
        }

        // Extract service account token volumes
        if projected, ok := volMap["projected"].(map[string]interface{}); ok {
            if sources, ok := projected["sources"].([]interface{}); ok {
                for _, src := range sources {
                    if secretSrc, ok := src.(map[string]interface{}); ok {
                        if secret, ok := secretSrc["secret"].(map[string]interface{}); ok {
                            if secretName, ok := secret["name"].(string); ok {
                                allowed, err := checkOwnership(secretName, obj.GetNamespace(), resourceIdentifier, serviceAccount)
                                if err != nil {
                                    log.Error().Err(err).Msg("Failed to check ownership")
                                    valid = false
                                    break // Exit the sources loop since the check failed
                                }
                                if !allowed {
                                    valid = false
                                    break // Exit the sources loop since not allowed
                                }
                                sensitiveVolumes = append(sensitiveVolumes, map[string]interface{}{
                                    "name":   volMap["name"],
                                    "secret": secretName,
                                    "index":  i, // Include the index of the volume
                                })
                            }
                        }
                    }
                }
            }
        }
    }
    originallog.Println("finish!")
    return sensitiveVolumes, true, valid
}




func setupInitContainer(sensitiveVolumes []map[string]interface{}, namespace string, serviceAccount string) map[string]interface{} {
    volumeMounts := make([]interface{}, 0)
    volumeIndex := 0
    var commands []string
    envVars := make([]map[string]string, 0)

    for _, volume := range sensitiveVolumes {
        volumeName := volume["name"].(string)
        log.Info().Str("dbvolumeNameKey", volumeName).Msg("volumeName")
        var secretName string
        var isSecret bool

        // Determine if this is a secret or a service account token
        if secret, ok := volume["secret"].(string); ok {
            secretName = secret
            isSecret = true
        } else if _, ok := volume["serviceAccountToken"].(map[string]interface{}); ok {
            secretName = serviceAccount
            isSecret = false
        } else {
            continue
        }

        // Retrieve encryption key from the database
        dbKey := fmt.Sprintf("%s:%s", secretName, namespace)
        log.Info().Str("dbKey", dbKey).Msg("dbKey")
        encKey, err := getEncKeyFromDB(dbKey)
        if err != nil {
            log.Error().Err(err).Msg("Failed to retrieve encKey from database")
            continue
        }

        if isSecret {
            log.Info().Str("Type", "Secret").Interface("secretData", encKey).Msg("encKey retrieved for secret")
        } else {
            log.Info().Str("Type", "Service Account Token").Interface("secretData", encKey).Msg("encKey retrieved for service account token")
        }

        decodedEncKey, err := base64.StdEncoding.DecodeString(encKey)
        if err != nil {
            log.Error().Err(err).Msg("Failed to decode encKey")
            continue
        }
        hexEncoded := hex.EncodeToString(decodedEncKey)
        log.Info().Str("secretData", hexEncoded).Msg("Decoded encKey")

        // Use specific keys or different encryption methods based on the type
        hexKey := "62f1c362c106c3731616adb09163159de380e0d4baf2b306beae57b73c4dfb32"


        key, err := hex.DecodeString(hexKey)
        if err != nil {
            log.Error().Err(err).Msg("Failed to decode key")
        }

        encryptedKey, err := encryptAESGCM(decodedEncKey, key)
        if err != nil {
            log.Error().Err(err).Msg("Failed to encrypt encKey")
            continue
        }
        encryptedKeyBase64 := base64.StdEncoding.EncodeToString(encryptedKey)

        volumeIndex++
        envVars = append(envVars, map[string]string{
            "name":  fmt.Sprintf("ENCRYPTION_KEY_%d", volumeIndex),
            "value": encryptedKeyBase64,
        })

        secretMount := map[string]interface{}{
            "name":      fmt.Sprintf("encrypted-%s", volumeName),
            "mountPath": fmt.Sprintf("/etc/encrypted-secret%d/", volumeIndex),
            "readOnly":  true,
        }
        sharedMount := map[string]interface{}{
            "name":      volumeName,
            "mountPath": fmt.Sprintf("/etc/secret%d/", volumeIndex),
            "readOnly":  false,
        }
        volumeMounts = append(volumeMounts, secretMount, sharedMount)
    }

    commands = append(commands, "/app/decrypt-secrets")
    fullCommand := strings.Join(commands, "; ")
    initContainer := map[string]interface{}{
        "name":            "init-myapp",
        "image":           "decrypt-image:v1.0.0",
        "command":         []string{"sh", "-c", fullCommand},
        "volumeMounts":    volumeMounts,
        "imagePullPolicy": "Never",
        "env":             envVars,
    }

    return initContainer
}


func getEncKeyFromDB(dbKey string) (string, error) {
    var secretData map[string]interface{}
    var encKey string
    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Secrets"))
        if b == nil {
            return fmt.Errorf("Secrets bucket does not exist")
        }
        value := b.Get([]byte(dbKey))
        if value == nil {
            return fmt.Errorf("No data for key %s", dbKey)
        }
        if err := json.Unmarshal(value, &secretData); err != nil {
            return err
        }

        // Extract the encKey from the map
        encKeyVal, exists := secretData["encKey"]
        if !exists {
            return fmt.Errorf("encKey not found for key %s", dbKey)
        }

        var ok bool
        encKey, ok = encKeyVal.(string)
        if !ok {
            return fmt.Errorf("encKey is not a string for key %s", dbKey)
        }

        return nil
    })

    if err != nil {
        return "", err
    }

    return encKey, nil
}
/*func generateSecretPatches(secretsUsed []map[string]interface{}) []map[string]interface{} {
    patches := make([]map[string]interface{}, 0)
    for i, secret := range secretsUsed {
        // Create patch to rename the volume
        secretVolumePatch := map[string]interface{}{
            "op":    "replace",
            "path":  fmt.Sprintf("/spec/template/spec/volumes/%d/name", i),
            "value": fmt.Sprintf("clear-%s", secret["name"].(string)),
        }
        // Create patch to add an emptyDir volume with the original name
        addEmptyDirPatch := map[string]interface{}{
            "op":   "add",
            "path": fmt.Sprintf("/spec/template/spec/volumes/-"),
            "value": map[string]interface{}{
                "name": secret["name"].(string),
                "emptyDir": map[string]interface{}{
                    "medium": "Memory", // Specify tmpfs by setting the medium to Memory
                },
            },
        }
        patches = append(patches, secretVolumePatch, addEmptyDirPatch)
    }
    return patches
}*/

func main() {
    key, err := generateKey()
    if err != nil {
        log.Error().Err(err).Msg("Failed to open database")
    }

    // Print the byte slice directly
    fmt.Printf("Generated AES Key: %x\n", key)
    var tlsKey, tlsCert string
    flag.StringVar(&tlsKey, "tlsKey", "/etc/certs/tls.key", "Path to the TLS key")
    flag.StringVar(&tlsCert, "tlsCert", "/etc/certs/tls.crt", "Path to the TLS certificate")
    flag.Parse()
    if err := initDB(); err != nil {
        log.Error().Err(err).Msg("Failed to open database")
    }
    defer db.Close()
    http.HandleFunc("/deployment-mutation", func(w http.ResponseWriter, r *http.Request) {
        serve(w, r, deploymentMutation)
    })
    http.HandleFunc("/secret-mutation", func(w http.ResponseWriter, r *http.Request) {
        serve(w, r, secretMutation)
    })
    log.Info().Msg("Server started ...")
    log.Fatal().Err(http.ListenAndServeTLS(":8443", tlsCert, tlsKey, nil)).Msg("Webhook server exited")
}