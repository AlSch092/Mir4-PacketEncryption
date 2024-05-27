# Mir4Encryption
Outbound Packet Encryption for Mir4 in C, the key changes on each patch while the IV stays static most of the time. The encryption method is AES256-CBC, which means it's a block cipher and usually requires a larger output buffer due to padding.

![Alt text](2.PNG?raw=true "Sample")   
![Alt text](clientlessM4.PNG?raw=true "Sample1")   
