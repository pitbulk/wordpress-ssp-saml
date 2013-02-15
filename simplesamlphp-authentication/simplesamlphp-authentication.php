<?php
/*
Plugin Name: simpleSAMLphp Authentication
Version: 0.6.3
Plugin URI: http://grid.ie/wiki/WordPress_simpleSAMLphp_authentication
Description: Authenticate users using <a href="http://rnd.feide.no/simplesamlphp">simpleSAMLphp</a>.
Author: David O'Callaghan
Author URI: http://www.cs.tcd.ie/David.OCallaghan/
*/

/* Copyright (C) 2009 David O'Callaghan (david.ocallaghan {} cs <> tcd <> ie)

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */


add_action('admin_menu', 'simplesaml_authentication_add_options_page');

$simplesaml_authentication_opt = get_option('simplesaml_authentication_options');

$simplesaml_configured = true;

// Try to configure the simpleSAMLphp client
if ($simplesaml_authentication_opt['include_path'] == '') {
	$simplesaml_configured = false;
} else { 
	$include_file = $simplesaml_authentication_opt['include_path']."/lib/_autoload.php";
	if (!include_once($include_file)) {
		$simplesaml_configured = false;
	}
}

if ($simplesaml_configured) {
	$sp_auth = ($simplesaml_authentication_opt['sp_auth'] == '') ? 'default-sp' : $simplesaml_authentication_opt['sp_auth'];
	$as = new SimpleSAML_Auth_Simple($sp_auth);
}

// plugin hooks into authentication system
add_action('wp_authenticate', array('SimpleSAMLAuthentication', 'authenticate'), 10, 2);
add_action('wp_logout', array('SimpleSAMLAuthentication', 'logout'));
add_action('lost_password', array('SimpleSAMLAuthentication', 'disable_function'));
add_action('retrieve_password', array('SimpleSAMLAuthentication', 'disable_function'));
add_action('password_reset', array('SimpleSAMLAuthentication', 'disable_function'));
add_filter('show_password_fields', array('SimpleSAMLAuthentication', 'show_password_fields'));


$slo = $simplesaml_authentication_opt['slo'];

if ($slo) {
	/*
	 Logout the user from wp if not exists an authenticated session at the simplesamlphp SP
	 This function overrides the is_logged_in function from wp core.
	 (Other solution could be to extend the wp_validate_auth_cookie func instead)
	*/
	function is_user_logged_in() {
		global $as;

		$user = wp_get_current_user();
		if ( $user->id > 0 ) {
			// User is local authenticated but SP session was closed
			if (!isset($as)) {
				global $simplesaml_authentication_opt;
				$sp_auth = ($simplesaml_authentication_opt['sp_auth'] == '') ? 'default-sp' : $simplesaml_authentication_opt['sp_auth'];
				$as = new SimpleSAML_Auth_Simple($sp_auth);
			}
			
			if(!$as->isAuthenticated()) {
				wp_logout();
				return false;
			} else {
				return true;
			}
		}
		return false;
	}
}


if (!class_exists('SimpleSAMLAuthentication')) {

	class SimpleSAMLAuthentication {
		
		// password used by the plugin
		function passwordRoot() {
			return 'Authenticated through SimpleSAML';
		}
		
		/*
		 We call simpleSAMLphp to authenticate the user at the appropriate time.
		 If the user has not logged in previously, we create an account for them.
		*/
		function authenticate(&$username, &$password) {
			global $simplesaml_authentication_opt, $simplesaml_configured, $as;
			
			if (!$simplesaml_configured) {
				die("simplesaml-authentication plugin not configured");
			}
			// Reset values from input ($_POST and $_COOKIE)
			$username = $password = '';
			
			$as->requireAuth();
			
			$attributes = $as->getAttributes();
			
			/*
			 * Only allow usernames that are not affected by sanitize_user(), and that are not
			 * longer than 60 characters (which is the 'user_login' database field length).
			 * Otherwise an account would be created but with a sanitized username, which might
			 * clash with an already existing account.
			 * See sanitize_user() in wp-includes/formatting.php.
			 */
			if(empty($simplesaml_authentication_opt['username_attribute'])) {
				$username = $attributes['uid'][0];
			} else {
				$username = $attributes[$simplesaml_authentication_opt['username_attribute']][0];
			}
			
			if ($username != substr(sanitize_user($username, TRUE), 0, 60)) {
				$error = sprintf(__('<p><strong>ERROR</strong><br /><br />
				We got back the following identifier from the login process:<pre>%s</pre>
				Unfortunately that is not suitable as a username.<br />
				Please contact the <a href="mailto:%s">blog administrator</a> and ask to reconfigure the
				simpleSAMLphp plugin!</p>'), $username, get_option('admin_email'));
				$errors['registerfail'] = $error;
				print($error);
				exit();
			}
			
			$password = md5(SimpleSAMLAuthentication::passwordRoot());
			
			if (!function_exists('get_user_by')) {
				die("Could not load user data");
			}
			
			$user = get_user_by('login', $username);
			
			if ($user) {
				// user already exists
				return true;
			} else {
				// First time logging in
				if ($simplesaml_authentication_opt['new_user'] == 1) {
					// Auto-registration is enabled
					// User is not in the WordPress database
					// They passed SimpleSAML and so are authorised
					// Add them to the database
					
					// User must have an e-mail address to register
					$user_email = '';
					$email_attribute = empty($simplesaml_authentication_opt['email_attribute']) ? 'mail' : $simplesaml_authentication_opt['email_attribute'];
						
					if($attributes[$email_attribute][0]) {
						// Try to get email address from attribute
						$user_email = $attributes[$email_attribute][0];
					} else {
						// Otherwise use default email suffix
						if ($simplesaml_authentication_opt['email_suffix'] != '') {
							$user_email = $username . '@' . $simplesaml_authentication_opt['email_suffix'];
						}
					}
					
					$user_info = array();
					$user_info['user_login'] = $username;
					$user_info['user_pass'] = $password;
					$user_info['user_email'] = $user_email;
					
					if(empty($simplesaml_authentication_opt['firstname_attribute'])) {
						$user_info['first_name'] = $attributes['givenName'][0];
					} else {
						$user_info['first_name'] = $attributes[$simplesaml_authentication_opt['firstname_attribute']][0];
					}
					
					if(empty($simplesaml_authentication_opt['lastname_attribute'])) {
						$user_info['last_name'] = $attributes['sn'][0];
					} else {
						$user_info['last_name'] = $attributes[$simplesaml_authentication_opt['lastname_attribute']][0];
					}
					
					// Set user role based on eduPersonEntitlement
					if ($simplesaml_authentication_opt['admin_entitlement'] != '' &&
						$attributes['eduPersonEntitlement'] &&
						in_array($simplesaml_authentication_opt['admin_entitlement'],
						$attributes['eduPersonEntitlement'])) {
						$user_info['role'] = "administrator";
					} else {
						$user_info['role'] = "author";
					}
					
					$wp_uid = wp_insert_user($user_info);
					
				} else {
					$error = sprintf(__('<p><strong>ERROR</strong>: %s is not registered with this blog.
						Please contact the <a href="mailto:%s">blog administrator</a> to create a new
						account!</p>'), $username, get_option('admin_email'));
					$errors['registerfail'] = $error;
					print($error);
					print('<p><a href="/wp-login.php?action=logout">Log out</a> of SimpleSAML.</p>');
					exit();
				}
			}
		}


		function logout() {
			global $simplesaml_authentication_opt, $simplesaml_configured, $as;
			if (!$simplesaml_configured) {
				die("simplesaml-authentication not configured");
			}
			$as->logout(get_settings('siteurl'));
		}

		// Don't show password fields on user profile page.
		function show_password_fields($show_password_fields) {
			return false;
		}

		function disable_function() {
			die('Disabled');
		}

	}
}

//----------------------------------------------------------------------------
//		ADMIN OPTION PAGE FUNCTIONS
//----------------------------------------------------------------------------

function simplesaml_authentication_add_options_page() {
	if (function_exists('add_options_page')) {
		add_options_page('simpleSAMLphp Authentication', 'simpleSAMLphp Authentication', 8,
			basename(__FILE__), 'simplesaml_authentication_options_page');
	}
}

function simplesaml_authentication_options_page() {
	global $wpdb;
	
	// Setup Default Options Array
	$optionarray_def = array(
		'new_user' => FALSE,
		'slo' => FALSE,
		'redirect_url' => '',
		'email_suffix' => 'example.com',
		'sp_auth' => 'default-sp',
		'username_attribute' => 'uid',
		'firstname_attribute' => 'givenName',
		'lastname_attribute' => 'sn',
		'email_attribute' => 'mail',
		'include_path' => '/var/simplesamlphp',
		'admin_entitlement' => '',
	);
  
	if (isset($_POST['submit']) ) {    
	// Options Array Update
	$optionarray_update = array (
		'new_user' => $_POST['new_user'],
		'slo' => $_POST['slo'],
		'redirect_url' => $_POST['redirect_url'],
		'email_suffix' => $_POST['email_suffix'],
		'include_path' => $_POST['include_path'],
		'sp_auth' => $_POST['sp_auth'],
		'username_attribute' => $_POST['username_attribute'],
		'firstname_attribute' => $_POST['firstname_attribute'],
		'lastname_attribute' => $_POST['lastname_attribute'],
		'email_attribute' => $_POST['email_attribute'],
		'admin_entitlement' => $_POST['admin_entitlement'],
	);

	update_option('simplesaml_authentication_options', $optionarray_update);
	}
  
	// Get Options
	$optionarray_def = get_option('simplesaml_authentication_options');
  
?>

<div class="wrap">
<h2>simpleSAMLphp Authentication Options</h2>
<form method="post" action="<?php echo $_SERVER['PHP_SELF'] . '?page=' . basename(__FILE__); ?>&updated=true">
<fieldset class="options">
<h3>User registration options</h3>
<table class="form-table">
	<tr valign="top">
		<th scope="row">User registration</th>
		<td>
		<label for="new_user"><input name="new_user" type="checkbox" id="new_user_inp" value="1" <?php checked('1', $optionarray_def['new_user']); ?> />Automatically register new users</label>
		<span class="setting-description">(Users will be registered with the role of Subscriber.)</span>
		</td>
	</tr>
	<!--
	<tr>
	<th><label for="email_suffix"> Default email domain</label></th>
	<td>
	<input type="text" name="email_suffix" id="email_suffix_inp" value="<?php echo $optionarray_def['email_suffix']; ?>" size="35" />
	<span class="setting-description">If an email address is not availble from the <acronym title="Identity Provider">IdP</acronym> <strong>username@domain</strong> will be used.</td>
	</tr>
	-->
	<tr>
		<th><label for="admin_entitlement">Administrator Entitlement URI</label></th>
		<td><input type="text" name="admin_entitlement" id="admin_entitlement_inp" value="<?php echo $optionarray_def['admin_entitlement']; ?>" size="40" />
		<span class="setting-description">An <a href="http://rnd.feide.no/node/1022">eduPersonEntitlement</a> URI to be mapped to the Administrator role.</span>
		</td>
	</tr>
</table>

<h3>simpleSAMLphp options</h3>
<p><em>Note:</em> Once you fill in these options, WordPress authentication will happen through <a href="http://rnd.feide.no/simplesamlphp">simpleSAMLphp</a>, even if you misconfigure it. To avoid being locked out of WordPress, use a second browser to check your settings before you end this session as Administrator. If you get an error in the other browser, correct your settings here. If you can not resolve the issue, disable this plug-in.</p>

<table class="form-table">
	<tr valign="top">
		<th scope="row"><label for="include_path">Path to simpleSAMLphp</label></th>
		<td><input type="text" name="include_path" id="include_path_inp" value="<?php echo $optionarray_def['include_path']; ?>" size="35" />
		<span class="setting-description">simpleSAMLphp suggested location is <tt>/var/simplesamlphp</tt>.</span> 
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="sp_auth">Authentication source</label></th> 
		<td><input type="text" name="sp_auth" id="sp_auth_inp" value="<?php echo $optionarray_def['sp_auth']; ?>" size="35" />
		<span class="setting-description">simpleSAMLphp default is "default-sp".</span> 
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="username_attribute">Attribute to be used as username</label></th> 
		<td><input type="text" name="username_attribute" id="username_attribute_inp" value="<?php echo $optionarray_def['username_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "uid".</span> 
		</td>
	</tr>

		<tr valign="top">
		<th scope="row"><label for="firstname_attribute">Attribute to be used as First Name</label></th> 
		<td><input type="text" name="firstname_attribute" id="firstname_attribute_inp" value="<?php echo $optionarray_def['firstname_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "givenName".</span> 
		</td>
	</tr>

		<tr valign="top">
		<th scope="row"><label for="lastname_attribute">Attribute to be used as Last Name</label></th> 
		<td><input type="text" name="lastname_attribute" id="lastname_attribute_inp" value="<?php echo $optionarray_def['lastname_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "sn".</span> 
		</td>
	</tr>

		<tr valign="top">
		<th scope="row"><label for="email_attribute">Attribute to be used as E-mail</label></th> 
		<td><input type="text" name="email_attribute" id="email_attribute_inp" value="<?php echo $optionarray_def['email_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "mail".</span> 
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="slo">Single Log Out</label></th>
		<td><input type="checkbox" name="slo" id="slo" value="1" <?php checked('1', $optionarray_def['slo']); ?> />
		<span class="setting-description">Enable Single Log out</span>
		</td>
	</tr>
</table>
</fieldset>
<div class="submit">
	<input type="submit" name="submit" value="<?php _e('Update Options') ?> &raquo;" />
</div>
</form>
<?php
}
?>
