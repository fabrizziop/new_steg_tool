# new_steg_tool
Encryption, plausible deniability and steganography tool, with WAV support.

This tool allows the user to encrypt a number of files (1 to 4), and create either an encrypted data file (indistinguishable from random), or place that data inside WAV audio files (Steganography). The scheme is designed to have independent encryption slots, allowing for plausible deniability. The only way to know a file is in a slot, is to successfully decrypt it. That operation, will not reveal any information about the other three slots. So anyone under duress could provide a password and slot with less important data.

Below, is the location of every piece of data inside the final data byte array. The only difference between saving the data as a file or as info inside WAV, is the size of the padding zones. "0:32" means byte 0 to byte 31, just like Python does it.

If an encryption slot isn't used, its corresponding data in the beginning and end of file is filled with random bytes.

*BEGINNING OF FILE*

|S1|S2|S3|S4|ESK1|ESK2|ESK3|ESK4|
|-|-|-|-|-|-|-|-|
|0:32|32:64|64:96|96:128|128:144|144:160|160:176|176:192|

|L1|L2|L3|L4|HMAC1-1|HMAC1-2|HMAC1-3|HMAC1-4
|-|-|-|-|-|-|-|-|
|192:208|208:224|224:240|240:256|256:320|320:384|384:448|448:512|

S1 to S4, each represent the salt bytes of each encryption slot. They are used to generate two encryption keys for slot, which are concatenated to create a 128 byte master key (per slot):

K_SCRYPT = SCRYPT(N=2^17, R=8, P=20, *SLOT PASSWORD*)
K_SHA512 = PBKDF2(iters=4000000, SHA512, *SLOT PASSWORD*)
K_MAIN = K_SCRYPT + K_SHA512

With the main key, four subkeys are derivated:

K_AES256 = SHA256(SHA512(K_MAIN))
K_HMAC1 = SHA256(SHA384(K_MAIN+K_MAIN))
K_HMAC2 = SHA256(SHA256(K_MAIN+K_MAIN+K_MAIN))
K_ESK = SHA256(SHA1(K_MAIN))

ESK1 to ESK4 are the encrypted shared final HMAC keys. A single 16 byte key is generated at the start of the encryption process. For every encryption slot used, the final HMAC key (HMACF_KEY) is XOR'd with K_ESK to create ESK1-ESK4.

At this point, each slot's stream cipher (AES256-CTR) is initialized, with K_AES256.

L1 to L4 represent each file's start and end position inside the encrypted data. Each 16 byte segment is divided into two 8-byte segments, the first one tells the program where the encrypted file data will begin inside the whole data blob. The second one, where it will end. Both are encoded little-endian, and are encrypted with the stream cipher.

HMAC1-1 to HMAC1-4 are HMAC_SHA512 checksums, that cover the integrity from S1 to L4. The key used for each slot's HMAC1 is K_HMAC1.

