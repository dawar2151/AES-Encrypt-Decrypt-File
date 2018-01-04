$ ./AES -e
Result: 0x66E94BD4EF8A2C3B884CFA59CA342B2E
# ./AES -d
Result: 0x140F0F1011B5223D79587717FFD9EC3A
- The second parameter, if given, will be the name of an existing file. The program will then have
produce in a new file the result of the encryption (case -e) or the decryption (case -d) of the
given file. For this, the CBC operating mode will be used and the initialization vector chosen will be
placed at the beginning of the product file. The key used will still be in this case that formed of 16 bytes
zero.
# ./AES -e butokuden.jpg
Butokuden.jpg encryption in aes-butokuden.jpg
$ ./AES -d aes-butokuden.jpg
Decryption of aes-butokuden.jpg in aes-aes-butokuden.jpg

- If a third parameter is given, it will be considered as a password: the program
as above, except for the choice of the key. This will be in this case the summary

MD5 of the password.
# $ echo -n "Alain" | md5
163f0dda0338e504f0a2ffc8abac45a2
# ./AES -e butokuden.jpg Alain
The key used is: 0x163F0DDA0338E504F0A2FFC8ABAC45A2
Butokuden.jpg encryption in aes-butokuden.jpg
# ./AES -d aes-butokuden.jpg Alain
The key used is: 0x163F0DDA0338E504F0A2FFC8ABAC45A2
Decryption of aes-butokuden.jpg in aes-aes-butokuden.jpg