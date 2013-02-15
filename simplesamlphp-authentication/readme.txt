=== Plugin Name ===
Contributors: davidoc, fkooman, usrlocaldick
Tags: authentication, saml, simpleSAMLphp
Requires at least: 3.0.0
Tested up to: 3.3.1
Stable tag: 0.6.3

Authenticate users using simpleSAMLphp

== Description ==

SimpleSAMLphp is a simple application written in native PHP that deals with
authentication. SimpleSAMLphp supports several federation protocols,
authentication mechanisms and can be used both for local authentication, as a
service provider or as an identity provider

This plugin uses some hooks in WordPress's authentication system to bypass the
normal login screen and authenticate using a simpleSAMLphp Service Provider
(SP) instead.  Note that logged-in state is still maintained in cookies, and
user entries are created in the local database.


== Installation ==

1. Download <a href="http://simplesamlphp.org/download">simpleSAMLphp</a> version 1.5 or higher on your web server and configure it <a href="http://simplesamlphp.org/docs/1.8/simplesamlphp-sp" title="SimpleSAMLphp Service Provider QuickStart">as a service provider</a>.
2. Upload `simplesaml-authentication.php` to the `wp-content/plugins/` directory of your WordPress installation.
3. Log in as administrator and activate the plugin. Go to the Options tab and configure the plugin. If applicable, configure an eduPersonEntitlement that will be mapped to the Administrator role. Decide which attribute to use for the username.  Take into consideration that the `sanatize_user()` function will be called on the value of this attribute (see `wp_includes/formatting.php`) which will remove anything but lowercase alphanumeric, space, dot, dash, and @-sign, and truncate it to 60 characters. A check is done to prevent creation of accounts with wrong usernames.
If the attribute you intend to use as username does have illegal characters, or is longer, you can work around this by using a hash of the username. Configure an extra attribute in simpleSAMLphp, for instance by applying an authproc filter like this:

		25 => array(
			'class' => 'core:PHP',
			'code' => '$attributes["wp_userid"] =
				array(hash("sha224", $attributes["id_with_slashes"][0]));',
		),
Then use `wp_userid` as the username attribute.  Now **STAY LOGGED IN** to your original administrator account.  You won't be able to log back in once you log out.
4. Open a different browser, or on another computer.  Log in to your blog to make sure that it works.
5. In the first browser window, make the newly created user an Administrator.  You can log out now. (Alternately, you can change some entries in the wp_usermeta table to make a new user the admin)
6. Disable Options -> General -> Anyone can register (they won't be able to)
7. Make sure you enable administration over SSL (see http://codex.wordpress.org/Administration\_Over_SSL)

== Frequently Asked Questions ==

= What version of simpleSAMLphp is needed? =
Starting from version 0.3.0 the plugin requires simpleSAMLphp 1.5 or higher. Use version 0.2.x of this plugin for simpleSAMLphp < 1.5 support.

== Changelog ==

= 0.6.3 =
* Fixed some bugs that occured when upgrading from 0.5.2 to 0.6.x

= 0.6.2 =
* Version bump

= 0.6.1 =
* Documentation formatting update

= 0.6.0 =
* Added check for illegal usernames
* Cleaned up indentation and bracket use
* Removed deprecated function calls
* Added configuration options to select which attributes to use for username, First Name, Last Name, E-mail
* Tested with 3.3.1 and simpleSAMLphp 1.8.2

= 0.5.2 =
* Added patch by Sixto Martin to provide single logout functionality

= 0.5.1 =
* Tested up to 3.1.4 alpha (svn18146)
* Tested with simpleSAMLphp 1.8

= 0.5.0 = 
* Upgrade plugin to support Wordpress 3.1
* Tested with simpleSAMLphp 1.7
* Fix logout, returns to home page now
* Modify attributes to map with default LDAP attributes (for differerent attribute names please use (or update!) the attibute mapping in the simpleSAMLphp SP configuration)

= 0.4.0 =
* Make it work again with latest WP (thanks to Ivo Jansch)

= 0.3.0 =
* Use simpleSAMLphp 1.5 API

= 0.2.1 =

== Upgrade Notice ==
Version 0.5.0 modified the preconfigured attributes in this plugin and now uses default LDAP attribute names. Please use the simpleSAMLphp configuration to 
match the SAML attributes to the default LDAP attributes to keep it working.
Version 0.6.0 introduced configurable attribute names, but kept the old hardcoded LDAP attributes as defaults.

== Who made this? ==

Thanks to <a href="http://wordpress.org/extend/plugins/profile/sms225">Stephen
Schwink</a> who developed the the <a
href="http://wordpress.org/extend/plugins/cas-authentication/">CAS
Authentication</a> plugin on which this plugin is heavily based.
