<?php
/**
 * @package    Auth
 * @version    1.0-$Id$
 * @link       http://github.com/gglnx/auth
 * @author     Dennis Morhardt <info@dennismorhardt.de>
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
 * 
 */
class Session {
	/**
	 * 
	 */
	public static $cookiehttp = false;
	
	/**
	 * 
	 */
	public static $cookiesecure = false;
	
	/**
	 * 
	 */
	public static $cookiedomain = null;
	
	/**
	 * 
	 */
	public static $cookiepath = '/';
	
	/**
	 * 
	 */
	public static $cookiename = 'SESAUT';
	
	/**
	 * 
	 */
	public static $secret = '123456789ABCDEF';
	
	/**
	 * 
	 */
	public static $expiration = 86400;
	
	/**
	 * 
	 */
	public static function create($username, $password) {
		// Generate expiration
		$expiration = time() + self::$expiration;
		
		// Generate cookie
		$pass_frag = substr($password, 8, 4);
		$key = hash_hmac('sha256', $username . $pass_frag . '|' . $expiration, self::$secret);
		$hash = hash_hmac('sha256', $username . '|' . $expiration, $key);
		$cookie = $username . '|' . $expiration . '|' . $hash;

		// Set cookie
		setcookie(self::$cookiename, $cookie . '|' . md5($cookie . self::$secret), $expiration, self::$cookiepath, self::$cookiedomain, self::$cookiesecure, self::$cookiehttp);
	}
	
	/**
	 * 
	 */
	public static function check($callback) {
		// Cookie exists?
		if ( !isset( $_COOKIE[self::$cookiename] ) )
			return false;
			
		// Parse cookie
		$cookie_elements = explode('|', $_COOKIE[self::$cookiename]);

		// Check if cookie has all parts
		if ( 4 != count( $cookie_elements ) )
			return self::destroy();

		// List the elements
		list($username, $expiration, $hmac, $md5) = $cookie_elements;
		
		// Check if the cookie was valid
		if ( $md5 != md5( $username . '|' . $expiration . '|' . $hmac . self::$secret ) )
			return self::destroy();
			
		// Check if the cookie hasn't expirated
		if ( time() > $expiration )
			return self::destroy();
			
		// Get user object from callback
		$user = $callback($username, $md5);

		// Check if a user was returned
		if ( false == $user || false == is_array( $user ) )
			return self::destroy();
			
		// Generate a hmac with the returned user data
		$pass_frag = substr($user['password'], 8, 4);
		$key = hash_hmac('sha256', $user['username'] . $pass_frag . '|' . $expiration, self::$secret);
		$hash = hash_hmac('sha256', $user['username'] . '|' . $expiration, $key);
		
		// Check if the hmacs are identical
		if ( $hmac != $hash )
			return self::destroy();
			
		// Return the user object if we got one
		if ( isset( $user['object'] ) ) 
			return $user['object'];
		
		// Return the username
		return $username;
	}
	
	/**
	 * 
	 */
	public static function destroy() {
		// Destroy the session
		setcookie(self::$cookiename, '', time() - 31536000, self::$cookiepath, self::$cookiedomain, self::$cookiesecure, self::$cookiehttp);
		
		return false;
	}
}
