Gibberish AES, a PHP Implementation
===================================

See Gibberish AES javascript encryption library, [https://github.com/mdp/gibberish-aes](https://github.com/mdp/gibberish-aes)

This class is based on initial code proposed by nbari at dalmp dot com
[http://www.php.net/manual/en/function.openssl-decrypt.php#107210](http://www.php.net/manual/en/function.openssl-decrypt.php#107210)

Live Demo
---------

http://iridadesign.com/starter-public-edition-4/www/playground/gibberish-aes

Requirements:
-----------------------------------

- OpenSSL functions installed and PHP version >= 5.3.3 (the preferred case)

or

- Mcrypt functions installed.

If none of these functions exist, the class will try to use openssl
from the command line (avoid this case).

Usage Example:
-----------------------------------

```php
echo '<br />';

// This is a secret key, keep it in a safe place and don't loose it.
$key = 'my secret key';
echo '$key = '.$key;
echo '<br />';
// The string to be encrypted.
$string = 'my secret message';
echo '$string = '.$string;
echo '<br />';
echo '<br />';

// The default key size is 256 bits.
$old_key_size = GibberishAES::size();

echo 'Encryption and decryption using a 256-bit key:';
echo '<br />';
GibberishAES::size(256);
// This is the result after encryption of the given string.
$encrypted_string = GibberishAES::enc($string, $key);
// This is the result after decryption of the previously encrypted string.
// $decrypted_string == $string (should be).
$decrypted_string = GibberishAES::dec($encrypted_string, $key);
echo '$encrypted_string = '.$encrypted_string;
echo '<br />';
echo '$decrypted_string = '.$decrypted_string;
echo '<br />';
echo '<br />';

echo 'Encryption and decryption using a 192-bit key:';
echo '<br />';
GibberishAES::size(192);
$encrypted_string = GibberishAES::enc($string, $key);
$decrypted_string = GibberishAES::dec($encrypted_string, $key);
echo '$encrypted_string = '.$encrypted_string;
echo '<br />';
echo '$decrypted_string = '.$decrypted_string;
echo '<br />';
echo '<br />';

echo 'Encryption and decryption using a 128-bit key:';
echo '<br />';
GibberishAES::size(128);
$encrypted_string = GibberishAES::enc($string, $key);
$decrypted_string = GibberishAES::dec($encrypted_string, $key);
echo '$encrypted_string = '.$encrypted_string;
echo '<br />';
echo '$decrypted_string = '.$decrypted_string;
echo '<br />';
echo '<br />';

// Restore the old key size.
GibberishAES::size($old_key_size);
```

Author: Ivan Tcholakov, 2012-2014.  
License: The MIT License (MIT), [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT)
