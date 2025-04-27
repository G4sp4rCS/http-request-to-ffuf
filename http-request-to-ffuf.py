#!/usr/bin/env python3
"""
HTTP Request Fuzzer - Converts HTTP requests from Burp Suite for use with ffuf
"""

import argparse
import re
import sys
import json
import urllib.parse
from typing import Dict, List, Optional, Tuple, Union


def print_banner():
    print(r"""
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
        """)



class HTTPRequest:
    def __init__(self):
        self.method = ""
        self.path = ""
        self.protocol = ""
        self.headers = {}
        self.body = ""
        self.host = ""
        self.port = None
        self.url = ""
        self.content_type = ""
        self.is_json = False
        self.is_form = False
        self.is_multipart = False

    def parse_request(self, request_text: str) -> None:
        """Parses a raw HTTP request."""
        lines = request_text.strip().split('\n')
        
        # Parse the request line (METHOD PATH PROTOCOL)
        request_line = lines[0].strip()
        parts = request_line.split(' ')
        if len(parts) >= 3:
            self.method = parts[0]
            self.path = parts[1]
            self.protocol = parts[2]
        
        # Parse headers
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if line == "":
                body_start = i + 1
                break
            
            if ':' in line:
                header_name, header_value = line.split(':', 1)
                self.headers[header_name.strip()] = header_value.strip()
        
        # Extract Host and construct URL
        if 'Host' in self.headers:
            self.host = self.headers['Host']
            if ':' in self.host:
                host_parts = self.host.split(':')
                self.host = host_parts[0]
                self.port = int(host_parts[1])
            
            # Determine protocol (http/https)
            protocol = "https" if self.port == 443 else "http"
            port_str = f":{self.port}" if self.port and self.port not in (80, 443) else ""
            self.url = f"{protocol}://{self.host}{port_str}{self.path}"
        
        # Extract body if it exists
        if body_start > 0 and body_start < len(lines):
            self.body = '\n'.join(lines[body_start:])
        
        # Determine content type
        if 'Content-Type' in self.headers:
            self.content_type = self.headers['Content-Type']
            self.is_json = 'application/json' in self.content_type
            self.is_form = 'application/x-www-form-urlencoded' in self.content_type
            self.is_multipart = 'multipart/form-data' in self.content_type

class FuzzerGenerator:
    def __init__(self, http_request: HTTPRequest, param_to_fuzz: str, wordlist: str):
        self.request = http_request
        self.param_to_fuzz = param_to_fuzz
        self.wordlist = wordlist
        self.fuzz_location = None  # url_param, body_param, json_field, header
        self.fuzz_position = None  # Specific position for fuzzing

    def find_param_location(self) -> bool:
        """Finds the location of the parameter to fuzz."""
        # Search in URL parameters
        if '?' in self.request.path:
            path, query = self.request.path.split('?', 1)
            params = urllib.parse.parse_qs(query)
            if self.param_to_fuzz in params:
                self.fuzz_location = 'url_param'
                return True
        
        # Search in form-urlencoded body
        if self.request.is_form and self.request.body:
            params = urllib.parse.parse_qs(self.request.body)
            if self.param_to_fuzz in params:
                self.fuzz_location = 'body_param'
                return True
        
        # Search in JSON
        if self.request.is_json and self.request.body:
            try:
                json_body = json.loads(self.request.body)
                # Recursive search in JSON
                if self._find_json_param(json_body, self.param_to_fuzz):
                    self.fuzz_location = 'json_field'
                    return True
            except json.JSONDecodeError:
                pass
        
        # Search in headers
        if self.param_to_fuzz in self.request.headers:
            self.fuzz_location = 'header'
            return True
        
        # Search in cookies
        if 'Cookie' in self.request.headers:
            cookies = self.request.headers['Cookie'].split(';')
            for cookie in cookies:
                if '=' in cookie:
                    name = cookie.split('=')[0].strip()
                    if name == self.param_to_fuzz:
                        self.fuzz_location = 'cookie'
                        return True
        
        return False

    def _find_json_param(self, json_obj: Union[Dict, List], param: str, path: str = "") -> bool:
        """Recursively searches for a parameter in a JSON object."""
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                new_path = f"{path}.{key}" if path else key
                if key == param:
                    self.fuzz_position = new_path
                    return True
                if isinstance(value, (dict, list)):
                    if self._find_json_param(value, param, new_path):
                        return True
        elif isinstance(json_obj, list):
            for i, item in enumerate(json_obj):
                new_path = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    if self._find_json_param(item, param, new_path):
                        return True
        return False

    def generate_ffuf_command(self) -> str:
        """Generates the ffuf command based on the parameter location."""
        if not self.fuzz_location:
            raise ValueError(f"Parameter '{self.param_to_fuzz}' not found in the request")
        
        cmd_parts = [f"ffuf -w {self.wordlist}"]
        
        # Add method
        cmd_parts.append(f"-X {self.request.method}")
        
        # Add base URL
        if self.fuzz_location == 'url_param':
            # Replace the parameter value in the URL with FUZZ
            path, query = self.request.path.split('?', 1)
            params = []
            for param in query.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    if name == self.param_to_fuzz:
                        params.append(f"{name}=FUZZ")
                    else:
                        params.append(param)
                else:
                    params.append(param)
            
            new_path = f"{path}?{'&'.join(params)}"
            url_parts = self.request.url.split('?', 1)
            base_url = url_parts[0]
            cmd_parts.append(f"-u \"{base_url}{new_path}\"")
        else:
            cmd_parts.append(f"-u \"{self.request.url}\"")
        
        # Add headers
        for name, value in self.request.headers.items():
            # Handle special case of fuzzing in headers or cookies
            if self.fuzz_location == 'header' and name == self.param_to_fuzz:
                cmd_parts.append(f"-H \"{name}: FUZZ\"")
            elif self.fuzz_location == 'cookie' and name == 'Cookie':
                cookies = []
                for cookie in value.split(';'):
                    if '=' in cookie:
                        cookie_name, cookie_value = cookie.split('=', 1)
                        cookie_name = cookie_name.strip()
                        if cookie_name == self.param_to_fuzz:
                            cookies.append(f"{cookie_name}=FUZZ")
                        else:
                            cookies.append(cookie.strip())
                    else:
                        cookies.append(cookie.strip())
                cmd_parts.append(f"-H \"Cookie: {'; '.join(cookies)}\"")
            else:
                cmd_parts.append(f"-H \"{name}: {value}\"")
        
        # Handle body
        if self.request.body and self.request.method in ('POST', 'PUT', 'PATCH'):
            if self.fuzz_location == 'body_param' and self.request.is_form:
                # Replace the parameter value in the form-urlencoded body
                params = []
                for param in self.request.body.split('&'):
                    if '=' in param:
                        name, value = param.split('=', 1)
                        if name == self.param_to_fuzz:
                            params.append(f"{name}=FUZZ")
                        else:
                            params.append(param)
                    else:
                        params.append(param)
                
                cmd_parts.append(f"-d \"{self.request.body}\"")
            elif self.fuzz_location == 'json_field' and self.request.is_json:
                # For JSON we need to use -fuzzing-mode for JSON path
                cmd_parts.append(f"-d '{self.request.body}'")
                cmd_parts.append(f"-mode pitchfork")
                # Use the JSON position found for FUZZ
                cmd_parts.append(f"-json '{self.fuzz_position}:FUZZ'")
            else:
                cmd_parts.append(f"-d '{self.request.body}'")
        
        return " ".join(cmd_parts)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Converts HTTP requests to ffuf commands')
    parser.add_argument('-p', '--param', required=True, help='Parameter to fuzz')
    parser.add_argument('-w', '--wordlist', required=True, help='Path to the wordlist')
    parser.add_argument('-r', '--request', help='File with the HTTP request (if not specified, reads from stdin)')
    parser.add_argument('-o', '--output', help='Output file for the ffuf command')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    
    args = parser.parse_args()
    
    # Read the request
    if args.request:
        try:
            with open(args.request, 'r') as f:
                request_text = f.read()
        except FileNotFoundError:
            print(f"Error: The file {args.request} does not exist.", file=sys.stderr)
            sys.exit(1)
    else:
        # Read from stdin
        if sys.stdin.isatty():
            print("Enter the HTTP request (press Ctrl+D when done):", file=sys.stderr)
        request_text = sys.stdin.read()
        if not request_text:
            print("Error: No HTTP request provided.", file=sys.stderr)
            sys.exit(1)
    
    # Process the request
    try:
        http_request = HTTPRequest()
        http_request.parse_request(request_text)
        
        fuzzer = FuzzerGenerator(http_request, args.param, args.wordlist)
        if not fuzzer.find_param_location():
            print(f"Error: The parameter '{args.param}' was not found in the request.", file=sys.stderr)
            sys.exit(1)
        
        ffuf_command = fuzzer.generate_ffuf_command()
        
        # Print verbose information
        if args.verbose:
            print(f"Method: {http_request.method}")
            print(f"URL: {http_request.url}")
            print(f"Parameter to fuzz: {args.param}")
            print(f"Parameter location: {fuzzer.fuzz_location}")
            if fuzzer.fuzz_position:
                print(f"JSON Position: {fuzzer.fuzz_position}")
            print("\nGenerated ffuf command:")
        
        # Save or print the command
        if args.output:
            with open(args.output, 'w') as f:
                f.write(ffuf_command)
            print(f"ffuf command saved to {args.output}")
        else:
            print(ffuf_command)
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
