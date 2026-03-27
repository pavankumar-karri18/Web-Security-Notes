### JWT (JSON Web Tokens)

#### Introduction
-   **What**: A popular token-based authentication method, especially for APIs where cookie-based authentication is less suitable.
-   **Documentation**: APIs using JWTs are often documented via Postman collections or Swagger/OpenAPI files.

#### JWT Structure
A JWT consists of three Base64-encoded parts separated by dots: `header.payload.signature`.
1.  **Header**: Contains metadata about the token, such as its type (`typ`, which is `JWT`) and the signing algorithm used (`alg`).
2.  **Payload**: Contains "claims," which are statements about an entity. Claims can be registered (standardized), public, or private.
3.  **Signature**: Used to verify the token's authenticity. It's created using the algorithm specified in the header.

#### Signing Algorithms
-   **None (`none`)**: No signature is used. This means there is no way to verify the token's integrity.
-   **Symmetric (`HS256`, `HS384`, `HS512`)**: A single secret key is used to both create and verify the signature.
-   **Asymmetric (`RS256`, `RS384`, `RS512`)**: A private key is used to sign the token, and a corresponding public key is used to verify it.

> **Tool**: [JWT.io](https://jwt.io/) is an excellent online tool for decoding, verifying, and generating JWTs.

---

### Common JWT Vulnerabilities & Fixes

#### 1. Sensitive Data Exposure
-   **Vulnerability**: Storing sensitive information, like plaintext or hashed passwords, directly within the JWT payload. Since the payload is only Base64 encoded, anyone can decode it and view the contents.
-   **Attack**: An attacker intercepts or obtains a JWT and simply Base64-decodes the payload part to read the sensitive data. No special tools are required.
-   **Fix**: Never store sensitive data in JWT claims.

#### 2. No Signature Verification
-   **Vulnerability**: The server decodes the token but fails to verify its signature. This allows an attacker to tamper with the payload (e.g., change user ID, elevate privileges) and the server will accept it.
-   **Vulnerable Code**:
    ```python
    # The server decodes the token without checking the signature.
    payload = jwt.decode(token, options={'verify_signature': False})
    ```
-   **Attack**: The attacker takes a valid token, decodes the payload, and modifies it to grant themselves higher privileges. For example, changing `"admin": false` to `"admin": true`. They then re-encode the token with the tampered payload and send it to the server. The server, not checking the signature, accepts the fraudulent claims.
    -   **Original Payload**: `{"username": "user", "admin": false, "iat": 1679875200}`
    -   **Tampered Payload**: `{"username": "user", "admin": true, "iat": 1679875200}`
-   **Fix**: Always verify the token signature against the correct secret or key and specify the expected algorithm.
    ```python
    # The server verifies the signature using the secret and a strong algorithm.
    payload = jwt.decode(token, self.secret, algorithms=["HS256"])
    ```

#### 3. Algorithm Downgrade Attack (`alg: none`)
-   **Vulnerability**: An attacker modifies the JWT header to set the algorithm to `none`. If the server's code is not configured to reject this, it may skip signature verification entirely, trusting the tampered payload.
-   **Vulnerable Code**:
    ```python
    # The server dynamically uses the algorithm from the token's header.
    header = jwt.get_unverified_header(token)
    signature_algorithm = header['alg']
    payload = jwt.decode(token, self.secret, algorithms=signature_algorithm)
    ```
-   **Attack**: The attacker takes a valid token, modifies the header to specify the `none` algorithm, and tampers with the payload (e.g., changing the username to `admin`). They then remove the signature part of the token. The resulting token has two parts separated by a dot, with a trailing dot to indicate an empty signature.
    -   **Tampered Header**: `{"typ": "JWT", "alg": "none"}`
    -   **Tampered Payload**: `{"username": "admin", "iat": 1679875200}`
    -   **Resulting Token**: `[base64_encoded_header].[base64_encoded_payload].`
-   **Fix**: Hardcode a list of accepted strong algorithms and reject any token that doesn't use one.
    ```python
    # The server only accepts tokens signed with specific, strong algorithms.
    payload = jwt.decode(token, self.secret, algorithms=["HS256", "HS384", "HS512"])
    ```

#### 4. Weak Symmetric Secrets
-   **Vulnerability**: If a weak or guessable secret is used for a symmetric algorithm (like HS256), an attacker can brute-force the secret using tools like `hashcat` or `johntheripper`. Once the secret is found, they can forge any token they want.
-   **Attack**: The attacker captures a valid JWT and uses a dictionary of common secrets to try and crack the signature. Once the weak secret (e.g., 'secret123') is discovered, they can create new, valid tokens with any payload they desire, such as one granting admin privileges.
    ```bash
    # Download a list of common secrets
    wget https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list
    # Use hashcat with a wordlist to find the secret key.
    # Mode 16500 is for JWT.
    hashcat -m 16500 -a 0 captured_jwt.txt common_secrets.list
    ```
-   **Fix**: Use a long, complex, and randomly generated secret for symmetric signing algorithms.

#### 5. Algorithm Confusion Attack (RS256 to HS256)
-   **Vulnerability**: A server is configured to accept tokens signed with both asymmetric (RS256) and symmetric (HS256) algorithms. An attacker can take a token signed with RS256, change the header's `alg` to HS256, and then re-sign the token using the *public key* as the secret. The server, expecting an HS256 token, will mistakenly use the public key to verify the signature, and the verification will succeed.
-   **Vulnerable Code**:
    ```python
    # The server accepts a wide range of algorithms, creating confusion.
    payload = jwt.decode(token, self.secret, algorithms=["HS256", "RS256"])
    ```
-   **Attack**: The attacker obtains the server's public key (which is often publicly available). They take a valid token, change the header algorithm from `RS256` to `HS256`, modify the payload as desired, and then sign the new token using the HS256 algorithm with the public key as the secret. The server will validate this signature successfully because it uses the same public key to verify what it thinks is an HS256 signature.
    -   **Original Header**: `{"typ": "JWT", "alg": "RS256"}`
    -   **Tampered Header**: `{"typ": "JWT", "alg": "HS256"}`
    -   **Signature**: `HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), public_key)`
-   **Fix**: The server code should handle symmetric and asymmetric algorithms separately, using the correct key (secret vs. public key) for each.
    ```python
    header = jwt.get_unverified_header(token)
    algorithm = header['alg']
    if "RS" in algorithm:
        payload = jwt.decode(token, self.public_key, algorithms=["RS256", "RS384", "RS512"])
    elif "HS" in algorithm:
        payload = jwt.decode(token, self.secret, algorithms=["HS256", "HS384", "HS512"])
    ```

#### 6. Improper Lifetime Management
-   **Vulnerability**: Tokens are issued without an expiration claim (`exp`) or with a very long lifetime. If a token is stolen, it grants the attacker persistent access. Unlike session cookies, JWTs cannot be easily invalidated on the server side without extra mechanisms (like a blocklist).
-   **Fix**: Always set a short and reasonable expiration time (`exp`) for tokens based on the application's security requirements.
    ```python
    lifetime = datetime.datetime.now() + datetime.timedelta(minutes=5)
    payload = {
        'username' : username,
        'admin' : 0,
        'exp' : lifetime
    }
    access_token = jwt.encode(payload, self.secret, algorithm="HS256")
    ```

#### 7. Cross-Service Relay Attacks
-   **Vulnerability**: In a system with a central authentication server serving multiple applications, a token intended for one application (`appA`) might be accepted by another (`appB`). If a user has admin rights in `appA`, an attacker could use that token to gain admin rights in `appB` if `appB` doesn't check the token's intended audience.
-   **Fix**: Always validate the audience (`aud`) claim to ensure the token is being used by the application it was issued for.
    ```python
    # The server specifies and verifies that the token is intended for "appA".
    payload = jwt.decode(token, self.secret, audience="appA", algorithms=["HS256"])
    ```
