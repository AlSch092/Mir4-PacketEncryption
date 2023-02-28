#include "Encryption.h"

//Alsch092 Github
//Do not change! Working just fine.
int Encryption::Encrypt(BYTE* packet, BYTE* outData, int Length)
{
	if (packet == NULL || Length < 1)
		return NULL;

	InitializeEncryptionKey((UINT64)EncryptionKey);

	int packetWithHeaderLength = Length + 5;
	byte* packetWithHeader = new byte[packetWithHeaderLength];

	memset(packetWithHeader + 1, 0, 4);

	memcpy((void*)&packetWithHeader[5], packet, Length); //write opcode + data after header, [7] is timestamp
	memcpy((void*)&packetWithHeader[0], (void*)&packetWithHeaderLength, 2);

	HMODULE MSVCP = LoadLibraryA("MSVCP120.dll");

	if (MSVCP) //this is required or your packet will disconnect
	{
		UINT64 ticks_addr = (UINT64)GetProcAddress(MSVCP, "_Xtime_get_ticks");

		if (ticks_addr)
		{
			//printf("ticks address: %llX\n", ticks_addr);
			InitializeGetTicks(ticks_addr);

			UINT64 timestamp = _GetPacketTimestamp(); //TODO: FIX THIS
			//printf("Got timestamp: %llX\n", timestamp);
			memcpy((void*)&packetWithHeader[7], (void*)&timestamp, sizeof(UINT64));
		}
	}
	else
	{
		printf("[ERROR] Could not get packet timestamp!\n");
		delete[] packetWithHeader;
		return NULL;
	}

	int nOffset = 0;
	int finalSendLength = packetWithHeaderLength + 14; //causes the length mismatch problem.. lea rbp, [rax+0x0e], and ebp 0x00FFFFF0
	finalSendLength = (finalSendLength & 0x00FFFFF0) + 1;

	typedef void(*encryptShell)(PVOID, PVOID);
	encryptShell _encrypt = (encryptShell)&EncryptPacketFunction; //since our version in .asm file was having trouble we can just call it as a char* buffer with exact bytes and patch over key location
	DWORD dwOldProt = 0;

	if (!VirtualProtect(&EncryptPacketFunction, 1000, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		delete[] packetWithHeader;
		return NULL;
	}

	UINT64 keyTableoffset = (UINT64)&EncryptionKey;
	UINT64 thisFunctionAddress = (UINT64)&EncryptPacketFunction;
	UINT64 KeyOffset = 0;

	KeyOffset = (keyTableoffset - thisFunctionAddress); //hackish method of putting key from our file into encrypto func which is a byte array and unmanagable
	KeyOffset -= 0x61;
	KeyOffset -= 4;
	memcpy((void*)(EncryptPacketFunction + 0x61), &KeyOffset, 4); //place offset to our key table into the 0x61st position of our byte* function

	//EVERY PACKET FIRST ENCRYPTS 16 BYTES, THEN DOES AN EDGE CASE (+1), THEN ENCRYPTS THE REST OF IT IN A LOOP OF 16 BYTES EACH TIME, WITH EACH TIME CALLING EACH FUNCTION (2 FUNCTIONS)
	_encrypt(packetWithHeader, TextCipherKey);

	nOffset += 0x10;
	byte bEdgeByte = packetWithHeader[15];

	bEdgeByte -= packetWithHeader[12]; //weird
	bEdgeByte -= packetWithHeader[9];
	bEdgeByte -= packetWithHeader[6];
	bEdgeByte -= packetWithHeader[3];
	bEdgeByte += packetWithHeader[14];
	bEdgeByte += packetWithHeader[13];
	bEdgeByte += packetWithHeader[11];
	bEdgeByte += packetWithHeader[10];
	bEdgeByte += packetWithHeader[8];
	bEdgeByte += packetWithHeader[7];
	bEdgeByte += packetWithHeader[5];
	bEdgeByte += packetWithHeader[4];
	bEdgeByte += packetWithHeader[2];
	bEdgeByte += packetWithHeader[1];
	bEdgeByte += packetWithHeader[0];

	packetWithHeader[16] = bEdgeByte;

	nOffset += 1;

	int nLoops = (finalSendLength - 0x12);
	nLoops = nLoops >> 4;
	nLoops = nLoops + 1;
	int loopOffset = 0;

	if (nOffset < finalSendLength)
	{
		for (int i = nLoops; i > 0; i--) //todo: try nloops vs nblock
		{
			_XorEncryptPacket(&packetWithHeader[nOffset], (&packetWithHeader[loopOffset])); //on 1st loop, noffset should be 0x11

			_encrypt(&packetWithHeader[nOffset], TextCipherKey); //function only encodes 16 bytes at a time.

			nOffset += 0x10;

			if (i == nLoops) //on first iteration, this is different
				loopOffset = 0x11;
			else
				loopOffset += 0x10;
		}
	}

	//printf("Encrypted (%d)\n", finalSendLength);
	memcpy((void*)&outData[0], (void*)packetWithHeader, finalSendLength);

	return finalSendLength;
}