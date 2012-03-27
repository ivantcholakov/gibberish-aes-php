
Gibberish AES, a PHP Implementation
===================================

See Gibberish AES javascript encryption library, [https://github.com/mdp/gibberish-aes](https://github.com/mdp/gibberish-aes)

This class is based on initial code proposed by nbari at dalmp dot com
[http://www.php.net/manual/en/function.openssl-decrypt.php#107210](http://www.php.net/manual/en/function.openssl-decrypt.php#107210)

Requirements:
-----------------------------------

OpenSSL functions installed and PHP version >= 5.3.3 (preferred case)
or
Mcrypt functions installed. 

Usage:
-----------------------------------

    // This is a secret key, keep it in a safe place and don't loose it.
    $key = 'my secret key';
    // The string to be encrypted.
    $string = 'my secret message';
    // This is the result after encryption of the given string.
    $encrypted_string = GibberishAES::enc($string, $key);
    // This is the result after decryption of the previously encrypted string.
    // $decrypted_string == $string (should be).
    $decrypted_string = GibberishAES::dec($encrypted_string, $key);

Author: Ivan Tcholakov, 2012.

License: Open Software License ("OSL") v 3.0, [http://www.opensource.org/licenses/OSL-3.0](http://www.opensource.org/licenses/OSL-3.0)
