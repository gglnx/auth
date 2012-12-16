<?php
/**
 * @package    Auth
 * @version    1.0-$Id$
 * @link       http://github.com/gglnx/auth
 * @author     Solar Designer <solar@openwall.com>
 *             Dennis Morhardt <info@dennismorhardt.de>
 * @copyright  Copyright 2012, Dennis Morhardt
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

namespace Auth;

/**
 * Based on the Portable PHP password hashing framework
 * by Solar Designer
 * http://www.openwall.com/phpass/
 */
class Password {
	/**
	 * 
	 */
	public static $iterationCountLog = 8;
	
	/**
	 * 
	 */
	private static $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
	
	/**
	 * 
	 */
	public static function check($password, $storedHash) {
		$hash = self::crypt($password, $storedHash);
		
		if ( $hash[0] == '*' ):
			$hash = crypt($password, $storedHash);
		endif;

		return $hash == $storedHash;
	}
	
	/**
	 * 
	 */
	public static function hash($password) {
		$random = self::getRandomBytes(6);
		$hash = self::crypt($password, self::generateSalt($random));
		
		if ( strlen( $hash ) == 34 ):
			return $hash;
		endif;

		// Returning '*' on error is safe here, but would _not_ be safe
		// in a crypt(3)-like function used _both_ for generating new
		// hashes and for validating passwords against existing hashes.
		return '*';
	}
	
	/**
	 * 
	 */
	private static function crypt($password, $setting) {
		$output = '*0';
		
		if ( substr( $setting, 0, 2 ) == $output )
			$output = '*1';

		$id = substr($setting, 0, 3);
		
		if ( $id != '$P$' )
			return $output;

		$count_log2 = strpos(self::$itoa64, $setting[3]);
		
		if ( $count_log2 < 7 || $count_log2 > 30 )
			return $output;

		$count = 1 << $count_log2;
		$salt = substr($setting, 4, 8);
		
		if ( strlen($salt) != 8 )
			return $output;

		// We're kind of forced to use MD5 here since it's the only
		// cryptographic primitive available in all versions of PHP
		// currently in use. To implement our own low-level crypto
		// in PHP would result in much worse performance and
		// consequently in lower iteration counts and hashes that are
		// quicker to crack (by non-PHP code).
		$hash = md5($salt . $password, TRUE);
		
		do {
			$hash = md5($hash . $password, TRUE);
		} while (--$count);
		
		$output = substr($setting, 0, 12);
		$output .= self::encode64($hash, 16);

		return $output;
	}

	/**
	 *
	 */
	private static function generateSalt($input) {
		$output = '$P$' . self::$itoa64[min(self::$iterationCountLog + 5, 30)];
		$output.= self::encode64($input, 6);

		return $output;
	}
	
	/**
	 *
	 */
	private static function encode64($input, $count) {
		$output = '';
		$i = 0;
		
		do {
			$value = ord($input[$i++]);
			$output .= self::$itoa64[$value & 0x3f];
			
			if ($i < $count)
				$value |= ord($input[$i]) << 8;
				
			$output .= self::$itoa64[($value >> 6) & 0x3f];
			
			if ($i++ >= $count)
				break;
				
			if ($i < $count)
				$value |= ord($input[$i]) << 16;
				
			$output .= self::$itoa64[($value >> 12) & 0x3f];
			
			if ($i++ >= $count)
				break;
				
			$output .= self::$itoa64[($value >> 18) & 0x3f];
		} while ($i < $count);

		return $output;
	}
	
	/**
	 *
	 */
	private static function getRandomBytes($count) {
		$output = '';
		
		if ( is_readable( '/dev/urandom' ) && ( $fh = @fopen( '/dev/urandom', 'rb' ) ) ):
			$output = fread($fh, $count);
			fclose($fh);
		endif;

		if ( strlen($output) < $count ):
			$output = '';
			$randomState = microtime();
		
			if ( function_exists( 'getmypid' ) )
				$randomState .= getmypid();
			
			for ( $i = 0; $i < $count; $i += 16 ):
				$randomState = md5(microtime() . $randomState);
				$output .= pack('H*', md5($randomState));
			endfor;
			
			$output = substr($output, 0, $count);
		endif;

		return $output;
	}
}
