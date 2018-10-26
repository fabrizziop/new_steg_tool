# new_steg_tool
Encryption, plausible deniability and steganography tool, with WAV support.

This tool allows the user to encrypt a number of files (1 to 4), and create either an encrypted data file (indistinguishable from random), or place that data inside WAV audio files (Steganography). The scheme is designed to have independent encryption slots, allowing for plausible deniability. The only way to know a file is in a slot, is to successfully decrypt it. That operation, will not reveal any information about the other three slots. So anyone under duress could provide a password and slot with less important data.

Below, is the location of every piece of data inside the final data byte array. The only difference between saving the data as a file or as info inside WAV, is the size of the padding zones. "0:32" means byte 0 to byte 31, just like Python does it.

If an encryption slot isn't used, its corresponding data in the beginning and end of file is filled with random bytes.

**BEGINNING OF FILE**

|S1|S2|S3|S4|ESK1|ESK2|ESK3|ESK4|
|-|-|-|-|-|-|-|-|
|0:32|32:64|64:96|96:128|128:144|144:160|160:176|176:192|

|L1|L2|L3|L4|HMAC1-1|HMAC1-2|HMAC1-3|HMAC1-4
|-|-|-|-|-|-|-|-|
|192:208|208:224|224:240|240:256|256:320|320:384|384:448|448:512|

S1 to S4, each represent the salt bytes of each encryption slot. They are used to generate two encryption keys for slot, which are concatenated to create a 128 byte master key (per slot):

K_SCRYPT = SCRYPT(N=2^17, R=8, P=20, **SLOT PASSWORD**)

K_SHA512 = PBKDF2(iters=4000000, SHA512, **SLOT PASSWORD**)

K_MAIN = K_SCRYPT + K_SHA512

With the main key, four subkeys are derivated:

K_AES256 = SHA256(SHA3_512(K_MAIN))

K_HMAC1 = SHA256(SHA3_384(K_MAIN+K_MAIN))

K_HMAC2 = SHA256(SHA3_256(K_MAIN+K_MAIN+K_MAIN))

K_ESK = SHA3_256(SHA1(K_MAIN))

ESK1 to ESK4 are the encrypted shared final HMAC keys. A single 16 byte key is generated at the start of the encryption process. For every encryption slot used, the final HMAC key (HMACF_KEY) is XOR'd with K_ESK to create ESK1-ESK4.

At this point, each slot's stream cipher (AES256-CTR) is initialized, with K_AES256.

L1 to L4 represent each file's start and end position inside the encrypted data. Each 16 byte segment is divided into two 8-byte segments, the first one tells the program where the encrypted file data will begin inside the whole data blob. The second one, where it will end. Both are encoded little-endian, and are encrypted with the stream cipher. Paddings and file locations are calculated just before this.

HMAC1-1 to HMAC1-4 are HMAC_SHA3_512 authentication constructions, that cover the integrity from S1 to L4. The key used for each slot's HMAC1 is K_HMAC1.

The main section of the resulting data from the encryption:

|P1|F1|P2|F2|P3|F3|P4|F4|P5|
|-|-|-|-|-|-|-|-|-|

P1 to P5 are padding zones, all made of random bytes, and each of a random length. For non-WAV-steganography usage, each padding zone is of a random length between MIN_PADSIZE_NONSTEG and MAX_PADSIZE_NONSTEG (0-1MB). For WAV steg usage, the total WAV storage capacity is first read from the WAV file. Then, the padding zones are adjusted randomly so the entire encryption data size is equal to the WAV capacity.

F1 to F4 are the zones where each slot's file will be stored. The already initialized AES256CTR cipher is used for each slot. If the slot isn't used, simply the F slot will not exist.

Data at the end of file.

|HMAC2-1|HMAC2-2|HMAC2-3|HMAC2-4|HMAC-FINAL|
|-|-|-|-|-|
|-320:-256|-256:-192|-192:-128|-128:-64|-64:|

HMAC2-1 to HMAC2-4 are HMAC constructions with SHA3_512, that cover the integrity from S1 to just before HMAC2-1. The key used for each slot's HMAC2 is K_HMAC2.

Because a possible attacker that controls the storage location (e.g. Dropbox) could carry this attack:

1. Alter one of the HMAC2.
2. See if the user detects corruption and replaces the file or does something unusual.
3. If the user doesn't react, the slot altered wasn't in usage (was just random data)

A solution to this was implemented. The Final HMAC integrity check is verified before HMAC2, and because there's a single HMAC and all slots have access to its key, by accessing a slot the user could know another slot's HMAC2 was altered and take (or not) appropiate measures. HMAC-FINAL is also HMAC_SHA3_512.

Suggestions, issues and bugfixes are welcome. Email me to PGP key:

> B48D57027501810FBE2538332C14F1ACFB154963

The usage of the program is at your own risk. I did the best I could.

** Changelog **

v2.0.0 - Switch from pycrypto to pycryptodome, switch some HMACs and normal hashes to SHA3 alternatives.
