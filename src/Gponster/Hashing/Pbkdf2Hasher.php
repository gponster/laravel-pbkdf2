<?php

/**
 * @author     Gponster <anhvudg@gmail.com>
 * @copyright  Copyright (c) 2014
 */
namespace Gponster\Hashing;

class Pbkdf2Hasher implements \Illuminate\Hashing\HasherInterface {

	/**
	 * Default iterations
	 *
	 * @var int
	 */
	public static $DEFAULT_ITERATIONS = 10000;

	/**
	 * Default salt length
	 *
	 * @var int
	 */
	public static $DEFAULT_SALT_LEN = 32;

	/**
	 * Default key length
	 *
	 * @var int
	 */
	public static $DEFAULT_KEY_LEN = 32;

	/**
	 * Minimum iterations
	 *
	 * @var int
	 */
	public static $MIN_ITERATIONS = 10000;

	/**
	 * Minimum salt length
	 *
	 * @var int
	 */
	public static $MIN_SALT_LEN = 32;

	/**
	 * Minimum key length
	 *
	 * @var int
	 */
	public static $MIN_KEY_LEN = 32;

	/**
	 * Hash the given value.
	 *
	 * @param string $value
	 * @param array $options
	 * @return string
	 */
	public function make($value, array $options = array()) {
		return static::hash($value, $options);
	}

	/**
	 * Check the given plain value against a hash.
	 *
	 * @param string $value
	 * @param string $hashedValue
	 * @param array $options
	 * @return bool
	 */
	public function check($value, $hashedValue, array $options = array()) {
		return static::verify($value, $hashedValue);
	}

	/*
	|--------------------------------------------------------------------------
	| Cost factor
	|--------------------------------------------------------------------------
	|
	| There are different methods of creating the password hash,
	| including a cost factor (what crynobone called a code factor).
	| It's also called 'rounds' in the Laravel code. Basically it's
	| the strength of the hash, or how difficult it is to compute.
	|
	| If the hashing method or cost factor (rounds) changes, new passwords
	| will use the new method, but old passwords will still be using the
	| old hash method from when they were created.  The old password hashes
	| will still pass the hash check algorithm correctly, but you may want
	| to update them to use the new hash method for security reasons.
	| That's what needsRehash() does. It checks to see if the hash is
	| using the current method and cost factor.  If it returns false,
	| that means you probably should re-compute the hash using the
	| current method. This is totally optional, but probably a good
	| idea if the new method is more secure.
	|
	*/

	/**
	 * Check if the given hash has been hashed using the given options.
	 *
	 * @param string $hashedValue
	 * @param array $options
	 * @return bool
	 * @see http://blog.stidges.com/post/upgrading-legacy-passwords-with-laravel
	 */
	public function needsRehash($hashedValue, array $options = array()) {
		$parts = explode('::', $hashedValue);
		if(count($parts) < 3) {
			return true;
		}

		$cost = (int)$parts[0];
		return $cost < static::$MIN_ITERATIONS;
	}

	/**
	 *
	 * @param string $password
	 * @return string
	 */
	public static function hash($password, $options = null) {
		$options = is_array($option) ? $options : array();

		$iterations = isset($options['iterations']) ? (int)$options['iterations'] : static::$DEFAULT_ITERATIONS;
		$saltLen = isset($options['salt_len']) ? (int)$options['salt_len'] : static::$DEFAULT_SALT_LEN;
		$keyLen = isset($options['key_len']) ? (int)$options['key_len'] : static::$DEFAULT_SALT_LEN;

		if($iterations < static::$MIN_ITERATIONS) {
			$iterations = static::$MIN_ITERATIONS;
		}

		if($saltLen < static::$MIN_SALT_LEN) {
			$saltLen = static::$MIN_SALT_LEN;
		}

		if($keyLen < static::$MIN_KEY_LEN) {
			$keyLen = static::$MIN_KEY_LEN;
		}

		$salt = static::key($saltLen);
		$derivedKey = hash_pbkdf2('sha1', $password, $salt, $iterations, $keyLen, true);
		$encodedDerivedKey = base64_encode($derivedKey);
		$encodedSalt = base64_encode($salt);

		return $iterations . '::' . $encodedSalt . '::' . $encodedDerivedKey;
	}

	public static function verify($password, $hashedPassword, array $options = array()) {
		$parts = explode('::', $hashedPassword);
		if(count($parts) < 3) {
			return false;
		}

		$iterations = $parts[0];
		$encodedSalt = $parts[1];
		$encodedDerivedKey = $parts[2];

		$derivedKey = base64_decode($encodedDerivedKey);
		$salt = base64_decode($encodedSalt);

		$keyLen = mb_strlen($derivedKey, 'ASCII');
		$hash = hash_pbkdf2('sha1', $password, $salt, $iterations, $keyLen, true);

		return $derivedKey === $hash;
	}

	public static function key($len = 5) {
		$key = '';
		$replace = array(
			'/', '+', '='
		);

		while(strlen($key) < $len) {
			$key .= str_replace($replace, NULL, base64_encode(mcrypt_create_iv($len, MCRYPT_RAND)));
		}

		return substr($key, 0, $len);
	}
}
