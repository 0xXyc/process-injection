# Process Injection Technique
### This repo consists of a basic self-injecting malware technique that is commonly seen in many different malicious files and families. Be sure to implement your own custom shellcode and encrypt it to try and beat Windows Defender and other end point security solutions!
### Message Box:
![image](https://github.com/0xXyc/process-injection/assets/42036798/9866327e-edf9-4e4d-8daa-834931f779a0)

This PoC is currently targetting Microsoft Edge! Make sure that it is running and you should be able to allocate memory within the process space of MS Edge, write the shellcode into that newly allocated region, and lastly execute the shellcode. 
