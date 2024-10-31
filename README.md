# Mir4 Encryption
Outbound Packet Encryption for Mir4 in C, the key changes each patch while the IV stays static across patches. The encryption method is AES256-CBC, which means it's a block cipher and usually requires a larger output buffer than input due to padding. Inbound data is not encrypted. 

A full client emulator for the game can be found in my other repo, Mir4-ClientEmulator. The .DLL compiled from this project is used with the client emulator to encrypt outbound data.

## Note
- You will have to update the encryption key for each new game patch. This means roughly once or twice a month; you can use cheat engine to find out which memory addresses access the IV  to find the in-game function that encrypts data, and update the key that way. I can update the keys for you for a small fee if you are unable to do this yourself

![Alt text](2.PNG?raw=true "Sample")   
![Alt text](clientlessM4.PNG?raw=true "Sample1")   
