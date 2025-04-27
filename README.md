# 🌐 http-request-to-ffuf

Easily grab an HTTP request and fuzz it with minimal effort! 🚀

## 📖 Overview

`http-request-to-ffuf` is a Python script designed to simplify fuzzing HTTP requests. By providing a request template, a parameter to fuzz, and a wordlist, you can quickly test for vulnerabilities or explore unknown endpoints.

## 🛠️ Usage

```bash
usage: fuzz.py [-h] -p PARAM -w WORDLIST [-r REQUEST] [-o OUTPUT] [-v]

Required arguments:
    -p, --param      The parameter to fuzz (e.g., `username`, `id`, etc.)
    -w, --wordlist   Path to the wordlist file for fuzzing

Optional arguments:
    -r, --request    Path to the HTTP request file (default: stdin)
    -o, --output     File to save the results
    -v, --verbose    Enable verbose output for debugging

┌──(kali㉿kali)-[~/Desktop/Proving-Grounds/Cockpit]
└─$ python3 fuzz.py -r request.txt -p username -w hugeSQL.txt -v

        "     __  __           _        _        
        |  \/  |         | |      | |       
        | \  / | __ _  __| | ___  | |__  _   _
        | |\/| |/ _` |/ _` |/ _ \ | '_ \| | | |
        | |  | | (_| | (_| |  __/ | |_) | |_| |
        |_|  |_|\__,_|\__,_|\___| |_.__/ \__, |
                                          __/ |
                                         |___/ 
                                _               
                               | |              
          __ _ _ __ _   _ _ __ | |_   __ _ _ __ 
         / _` | '__| | | | '_ \| __| / _` | '__|
        | (_| | |  | |_| | | | | |_ | (_| | |   
         \__, |_|   \__,_|_| |_|\__(_)__,_|_|   
          __/ |                                
         |___/  
        
Method: POST
URL: http://192.168.244.10/login.php
Parameter to fuzz: username
Parameter location: body_param

Generated ffuf command:
ffuf -w hugeSQL.txt -X POST -u "http://192.168.244.10/login.php" -H "Host: 192.168.244.10" -H "Content-Length: 29" -H "Cache-Control: max-age=0" -H "Accept-Language: en-US,en;q=0.9" -H "Origin: http://192.168.244.10" -H "Content-Type: application/x-www-form-urlencoded" -H "Upgrade-Insecure-Requests: 1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" -H "Referer: http://192.168.244.10/login.php" -H "Accept-Encoding: gzip, deflate, br" -H "Cookie: PHPSESSID=t8mp0410dd3b9c3qev33agor9r" -H "Connection: keep-alive" -d "username=admin&password=admin"
                                                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/Desktop/Proving-Grounds/Cockpit]
└─$ 

```

### Example Error Message

```bash
fuzz.py: error: the following arguments are required: -p/--param, -w/--wordlist
```

## 🔍 Example Usage

### 1️⃣ Basic Example

Suppose you want to fuzz the `username` parameter in a login request using a wordlist called `users.txt`. Here's how you can do it:

```bash
python fuzz.py -p username -w users.txt -r request.txt
```

### 2️⃣ Save Results to a File

To save the output to a file named `results.txt`:

```bash
python fuzz.py -p username -w users.txt -r request.txt -o results.txt
```

### 3️⃣ Verbose Mode

Enable verbose mode to see detailed output:

```bash
python fuzz.py -p username -w users.txt -r request.txt -v
```

## 📂 Input Request Format

The HTTP request file (`request.txt`) should follow this format:

```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=FUZZ&password=12345
```

Here, `FUZZ` is the placeholder that will be replaced by each word in the wordlist.

## 🎉 Features

- 🔄 Flexible parameter fuzzing
- 📜 Supports custom HTTP request files
- 💾 Save results to a file
- 🐛 Debugging with verbose mode

## ⚠️ Notes

- Ensure your wordlist is appropriate for the target.
- Use responsibly and only on systems you have permission to test.

Happy fuzzing! 🎯
