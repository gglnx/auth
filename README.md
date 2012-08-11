Auth
====

Simple auth class for PHP 5.3+ based on cookies. Also included a password hash class based on phpass (http://www.openwall.com/phpass/) 0.3.

Using Auth
----------

### Checking if a user is currently logged in

If the current session is valid you get the User model object as return value.

```php
$user = Auth\Session::check(function($user, $md5) {
	$user = User::findOne()->is('username', $user)->select();
	return array('username' => $user->username, 'password' => $user->password, 'object' => $user);
});
```