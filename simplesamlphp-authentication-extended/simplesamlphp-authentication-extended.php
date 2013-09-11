<?php
/*
Plugin Name: simpleSAMLphp Authentication (smartin version)
Version: 0.3
Plugin URI: https://github.com/pitbulk/wordpress-saml
Description: Description: Authenticate users using <a href="http://simplesamlphp.org">simpleSAMLphp</a>.
Plugin based on: http://wordpress.org/plugins/simplesamlphp-authentication
*/

/* Copyright (C) 2013 David O'Callaghan (david.ocallaghan {} cs <> tcd <> ie)

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
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 

*/


add_action('admin_menu', 'simplesaml_authentication_extended_add_options_page');

$simplesaml_authentication_extended_opt = get_option('simplesaml_authentication_extended_options');

$simplesaml_configured = true;

// Try to configure the simpleSAMLphp client
if ($simplesaml_authentication_extended_opt['include_path'] == '') {
	$simplesaml_configured = false;
} else { 
	$include_file = $simplesaml_authentication_extended_opt['include_path']."/lib/_autoload.php";
	if (!include_once($include_file)) {
		$simplesaml_configured = false;
	}
}

if ($simplesaml_configured) {
	$sp_auth = ($simplesaml_authentication_extended_opt['sp_auth'] == '') ? 'default-sp' : $simplesaml_authentication_extended_opt['sp_auth'];
        try {
		$as = new SimpleSAML_Auth_Simple($sp_auth);
	}
	catch (Exception $e) {
		$as = NULL;
                $simplesaml_configured = false;		
	}
}

// plugin hooks into authenticator system
add_action('authenticate', array('SimpleSAMLAuthenticator', 'authenticate'), 10, 2);
add_action('wp_logout', array('SimpleSAMLAuthenticator', 'logout'));
add_action('lost_password', array('SimpleSAMLAuthenticator', 'disable_function'));
add_action('retrieve_password', array('SimpleSAMLAuthenticator', 'disable_function'));
add_action('password_reset', array('SimpleSAMLAuthenticator', 'disable_function'));
add_filter('show_password_fields', array('SimpleSAMLAuthenticator', 'show_password_fields'));

if ($simplesaml_authentication_extended_opt['redirect_main_page']) {
    add_filter('login_redirect', array('SimpleSAMLAuthenticator', 'change_login_redirect'), 100, 3);
}


// Version logic
$version = '0.7.0';
$previous_version = get_option('simplesaml_authentication_extended_version');
if($previous_version){
	/*
	#Version comparison. Not yet needed as this is the first release that has a database version number.
	if(version_compare($version, $db_version) === 1) {
		Upgrade stuff here...
	}
	*/
} else {
	# No previous version detected -> that means possibly vulnerable passwords
	fix_vulnerable_passwords();
	update_option('simplesaml_authentication_extended_version', $version);
}


function fix_vulnerable_passwords() {
	global $wpdb;
	require_once( ABSPATH . 'wp-includes/class-phpass.php' );
	$wp_hasher = new PasswordHash(8, true);
	$users = $wpdb->get_results("SELECT * FROM wp_users");

	foreach($users as $user) {
		if($wp_hasher->CheckPassword(md5('Authenticated through SimpleSAML'), $user->user_pass)) {
			invalidate_password($user->ID);
		}
	}
}

function invalidate_password($ID) {
	global $wpdb;
	$wpdb->query(
		$wpdb->prepare(
			"UPDATE wp_users SET user_pass = '~~~invalidated_password~~~' WHERE ID = %d",
			$ID
		)
	);
}


$slo = $simplesaml_authentication_extended_opt['slo'];

if ($slo) {
	/*
	 Log the user out from WordPress if the simpleSAMLphp SP session is gone.
	 This function overrides the is_logged_in function from wp core.
	 (Another solution could be to extend the wp_validate_auth_cookie func instead).
	*/
	function is_user_logged_in() {
		global $as;

		$user = wp_get_current_user();
		if ( $user->ID > 0 ) {
			// User is local authenticated but SP session was closed
			if (!isset($as)) {
				global $simplesaml_authentication_extended_opt;
				$sp_auth = ($simplesaml_authentication_extended_opt['sp_auth'] == '') ? 'default-sp' : $simplesaml_authentication_extended_opt['sp_auth'];
				try {
					$as = new SimpleSAML_Auth_Simple($sp_auth);
				}
				catch (Exception $e) {
					return false;
				}
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


if (!class_exists('SimpleSAMLAuthenticator')) {

	class SimpleSAMLAuthenticator {
		
		/*
		 We call simpleSAMLphp to authenticate the user at the appropriate time.
		 If the user has not logged in previously, we create an account for them.
		*/
		function authenticate($user, $username) {
            if(is_a($user, 'WP_User')) { return $user; }

			global $simplesaml_authentication_extended_opt, $simplesaml_configured, $as;
			
			if (!$simplesaml_configured) {
				die("simplesaml-authentication plugin not configured");
			}

			try {	
				$as->requireAuth();
			}
			catch (Exception $e) {
				die("SAML login could not be initiated");
			}


            // Reset values from input ($_POST and $_COOKIE)
            $username = '';
			
			$attributes = $as->getAttributes();

			if(empty($simplesaml_authentication_extended_opt['username_attribute'])) {
				$username = $attributes['uid'][0];
			} else if (!empty($attributes[$simplesaml_authentication_extended_opt['username_attribute']])) {
				$username = $attributes[$simplesaml_authentication_extended_opt['username_attribute']][0];
			}
            else {
                die("Could not retrieve user_id from the saml assertion");
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
			
			$user = get_user_by('login', $username);
			
			if ($user) {
				// user already exists
				return $user;
			} else {
				// First time logging in
				if ($simplesaml_authentication_extended_opt['new_user'] == 1) {
					// Auto-registration is enabled
					// User is not in the WordPress database
					// They passed SimpleSAML and so are authorised
					// Add them to the database
					
					// User must have an e-mail address to register
					$user_email = '';
					$email_attribute = empty($simplesaml_authentication_extended_opt['email_attribute']) ? 'mail' : $simplesaml_authentication_extended_opt['email_attribute'];
						
					if($attributes[$email_attribute][0]) {
						// Try to get email address from attribute
						$user_email = $attributes[$email_attribute][0];
					} else {
						// Otherwise use default email suffix
						if ($simplesaml_authentication_extended_opt['email_suffix'] != '') {
							$user_email = $username . '@' . $simplesaml_authentication_extended_opt['email_suffix'];
						}
					}
					
					$user_info = array();
					$user_info['user_login'] = $username;
					$user_info['user_pass'] = 'dummy'; // Gets reset later on.
					$user_info['user_email'] = $user_email;
					
					if(empty($simplesaml_authentication_extended_opt['firstname_attribute'])) {
						$user_info['first_name'] = $attributes['givenName'][0];
					} else {
						$user_info['first_name'] = $attributes[$simplesaml_authentication_extended_opt['firstname_attribute']][0];
					}
					
					if(empty($simplesaml_authentication_extended_opt['lastname_attribute'])) {
						$user_info['last_name'] = $attributes['sn'][0];
					} else {
						$user_info['last_name'] = $attributes[$simplesaml_authentication_extended_opt['lastname_attribute']][0];
					}
					
					// Set user role based on eduPersonEntitlement
					if ($simplesaml_authentication_extended_opt['admin_entitlement'] != '' &&
						$attributes['eduPersonEntitlement'] &&
						in_array($simplesaml_authentication_extended_opt['admin_entitlement'],
						$attributes['eduPersonEntitlement'])) {
						$user_info['role'] = "administrator";
					}
					else if($simplesaml_authentication_extended_opt['default_role'] != '') {
						$user_info['role'] = $simplesaml_authentication_extended_opt['default_role'];
					}
					else {
						$user_info['role'] = "author";
					}
					
					$wp_uid = wp_insert_user($user_info);

					if ( is_object($wp_uid) && is_a($wp_uid, 'WP_Error') ) {
						$error = $wp_uid->get_error_messages();
						$error = implode("<br>", $error);
						$error = '<p><strong>ERROR</strong>: '.$error.'</p>';
						print_r($error);
						$errors['registerfail'] = $error;
						exit();            
					}

					invalidate_password($wp_uid);
					return get_user_by('login', $username);
				} else {
					$error = sprintf(__('<p><strong>ERROR</strong>: %s is not registered with this blog.
						Please contact the <a href="mailto:%s">blog administrator</a> to create a new
						account!</p>'), $username, get_option('admin_email'));
					$errors['registerfail'] = $error;
					print($error);
					print('<p><a href="/wp-login.php?action=logout">Log out</a> of SimpleSAMLphp.</p>');
					exit();
				}
			}
		}


		function logout() {
			global $simplesaml_authentication_extended_opt, $simplesaml_configured, $as;
			if (!$simplesaml_configured) {
				die("simplesaml-authentication not configured");
			}
			$as->logout(get_option('siteurl'));
		}

		// Don't show password fields on user profile page.
		function show_password_fields($show_password_fields) {
			return false;
		}

		function disable_function() {
			die('Disabled');
		}

        function change_login_redirect() {
            wp_redirect(get_home_url());
            die();
        }

	}
}

//----------------------------------------------------------------------------
//		ADMIN OPTION PAGE FUNCTIONS
//----------------------------------------------------------------------------

function simplesaml_authentication_extended_add_options_page() {
	if (function_exists('add_options_page')) {
		add_options_page('simpleSAMLphp Authentication', 'simpleSAMLphp Authentication', 'manage_options',
			basename(__FILE__), 'simplesaml_authentication_extended_options_page');
	}
}

function simplesaml_authentication_extended_options_page() {
	global $wpdb;
	
	// Default options
	$options = array(
		'new_user' => FALSE,
		'slo' => FALSE,
		'redirect_main_page' => FALSE,
		'email_suffix' => 'example.com',
		'sp_auth' => 'default-sp',
		'username_attribute' => 'uid',
		'firstname_attribute' => 'givenName',
		'lastname_attribute' => 'sn',
		'email_attribute' => 'mail',
		'include_path' => '/var/simplesamlphp',
		'admin_entitlement' => '',
		'default_role' => 'author',
	);
  
	if (isset($_POST['submit']) ) {
		// Create updated options, loop through original one to get keys.
		$options_updated = array();
		foreach(array_keys($options) as $key) {
			$options_updated[$key] = isset($_POST[$key]) ? $_POST[$key] : $options[$key];
		}

		update_option('simplesaml_authentication_extended_options', $options_updated);

    }
  
	// Get Options
	$options = get_option('simplesaml_authentication_extended_options');
  
?>

<div class="wrap">
<h2>SimpleSAMLphp Authentication Options</h2>
<form method="post" action="<?php echo $_SERVER['PHP_SELF'] . '?page=' . basename(__FILE__); ?>&updated=true">
<fieldset class="options">
<h3>User registration options</h3>
<table class="form-table">
	<tr valign="top">
		<th scope="row">User registration</th>
		<td>
		<label for="new_user"><input name="new_user" type="checkbox" id="new_user_inp" value="1" <?php checked('1', $options['new_user']); ?> />Automatically register new users</label>
		<span class="setting-description">(Users will be registered with default role.)</span>
		</td>
	</tr>
	<tr>
		<th><label for="default_role">Default Role</label></th>
		<td><input type="text" name="default_role" id="default_role_inp" value="<?php echo $options['default_role']; ?>" size="40" />
		<span class="setting-description">The default WordPress role for new users (e.g. author or subscriber).</span>
		</td>
	</tr>
	<tr>
		<th><label for="admin_entitlement">Administrator Entitlement URI</label></th>
		<td><input type="text" name="admin_entitlement" id="admin_entitlement_inp" value="<?php echo $options['admin_entitlement']; ?>" size="40" />
		<span class="setting-description">An <a href="http://rnd.feide.no/node/1022">eduPersonEntitlement</a> URI to be mapped to the Administrator role.</span>
		</td>
	</tr>
</table>

<h3>simpleSAMLphp options</h3>
<p><em>Note:</em> Once you fill in these options, WordPress authentication will happen through <a href="http://simplesamlphp.org">simpleSAMLphp</a>, even if you misconfigure it. To avoid being locked out of WordPress, use a second browser to check your settings before you end this session as Administrator. If you get an error in the other browser, correct your settings here. If you can not resolve the issue, disable this plug-in.</p>

<table class="form-table">
	<tr valign="top">
		<th scope="row"><label for="include_path">Path to simpleSAMLphp</label></th>
		<td><input type="text" name="include_path" id="include_path_inp" value="<?php echo $options['include_path']; ?>" size="35" />
		<span class="setting-description">simpleSAMLphp suggested location is <tt>/var/simplesamlphp</tt>.</span> 
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="sp_auth">Authentication source</label></th> 
		<td><input type="text" name="sp_auth" id="sp_auth_inp" value="<?php echo $options['sp_auth']; ?>" size="35" />
		<span class="setting-description">simpleSAMLphp default is "default-sp".</span> 
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="username_attribute">Attribute to be used as username</label></th> 
		<td><input type="text" name="username_attribute" id="username_attribute_inp" value="<?php echo $options['username_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "uid".</span> 
		</td>
	</tr>

		<tr valign="top">
		<th scope="row"><label for="firstname_attribute">Attribute to be used as First Name</label></th> 
		<td><input type="text" name="firstname_attribute" id="firstname_attribute_inp" value="<?php echo $options['firstname_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "givenName".</span> 
		</td>
	</tr>

		<tr valign="top">
		<th scope="row"><label for="lastname_attribute">Attribute to be used as Last Name</label></th> 
		<td><input type="text" name="lastname_attribute" id="lastname_attribute_inp" value="<?php echo $options['lastname_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "sn".</span> 
		</td>
	</tr>

		<tr valign="top">
		<th scope="row"><label for="email_attribute">Attribute to be used as E-mail</label></th> 
		<td><input type="text" name="email_attribute" id="email_attribute_inp" value="<?php echo $options['email_attribute']; ?>" size="35" />
		<span class="setting-description">Default is "mail".</span> 
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="slo">Single Log Out</label></th>
		<td><input type="checkbox" name="slo" id="slo_inp" value="1" <?php checked('1', $options['slo']); ?> />
		<span class="setting-description">Enable Single Log out</span>
		</td>
	</tr>

	<tr valign="top">
		<th scope="row"><label for="redirect_main_page">Redirect to main page after login</label></th>
		<td><input type="checkbox" name="redirect_main_page" id="redirect_main_page_inp" value="1" <?php checked('1', $options['redirect_main_page']); ?> />
		<span class="setting-description">Enable if you want to redirect the user to the main page instead of the admin panel</span>
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
