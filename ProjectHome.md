This project provides tools to store hidden data in jpeg DCT coefficients: steganographic C library together with a simple command line tool, that uses the library.

It shall be noted that because of rather straightforward steganographic method used, the presence of messages is likely to be discoverable by using contemporary statistical steganodetection methods.
Concisely: don't rely on it blindly.


### Encoding process ###
By given password, data buffer and jpeg file encoding function creates another, modified jpeg file with some DCT coefficients modified to hold the message. Data carrying coefficients are selected randomly from available, this is done by generating a long shuffle. PRNG, is seeded by password hash. A pack of data: (message length, message, message SHA1 sum) - is ciphered with BLOWFISH stream cipher and embedded into selected DCT coefficients.


### Decoding process ###
By given password, decoding function seeds PRNG and finds sequence of bits, that hold message. There may be no message, of cause.  Then it tries to detect payload length marker by unciphering a piece of message from the beginning. IF OK, the program reads and decrypts what is supposed to be the message and it's checksum. If message checksum matches the message, the decoding process succeeds.

# Miscellaneous ideas #
### Embedding a bit ###
To store a bit slightly modified LSB coding is used. Classical LSB coding is vulnerable to the fact that e.g. 9 would never shift to 10, only to 8 in coding process (9 has it's LSB equal to 1, if we modify it blindly to hold what we need, we will only get 8 or 9). To avoid this, when we need to change LSB,
we make it randomly up or down ( 9->10 or 9->8 with 1/2 probability if we need LSB = 0), taking random from external source (/dev/urandom).

### PRNG ###
To make PRNG Blowfish cipher is used. We set up block cipher
and start to cipher 64 bit integers: 0,1,2,3.... This generates stream of bytes, that's our PRNG.

### Cipher ###
The same Blowfish cipher is used to cipher data. Data cipher is initialized by secret text, while PRNG cipher is initialized by text SHA1 hash.

### DCT coefficient choice ###
A DCT block is a 8x8 matrix of values. The higher ` (i^2 + j^2) ` of the pair is, the shorter wavelength it respects to. It would be unwise to use all of the coefficients to carry data, because the higher are usual to be zero.

To deal with the problem, only those cells, which are next to (0,0) should be used. We use this condition to select the appropriate:
```
i^2 + j^2 <= DCT_radius^2
```
The library doesn't specify DCT\_radius value.
The value, used in utility, is 2