<?php
/**
 * Plugin Name:     SAAD-IT Login Attempts Logger
 * Description:     Plugin logs invalid or valid wp login attempts via a $log_file, including passwords for invalid attempts
 * Version:         1.5
 * Author:          ksaadDE
 * Author URI:      https://saad-it.de/
 * Update URI:      https://github.com/saaditDE/saadit-login-logger
 */

// Exit if accessed directly
if (!defined('ABSPATH'))
{
    exit;
}


// Logfile Path Def
function getLogFile()
{
    $log_file = 'login-log.php';
    return plugin_dir_path(__FILE__) . $log_file;
}


function getUser($username)
{
    if(empty($username) || is_null($username))
        return false;

    $user = get_user_by('login', $username);
    if(!$user || $user == null || $user == false || !($user instanceof WP_User) || is_null($user) || empty($user))
        return false;
    return $user;
}

function checkPassword($user, $password)
{
    if (!($user instanceof WP_User))
        return false;

    return wp_check_password($password, $user->user_pass, $user->ID);
}

function log_login_attempt($user, $error = null)
{
    // Get the IP address of the user
    $ip_address = $_SERVER['REMOTE_ADDR'];
    $timestamp = current_time('mysql');


    $username=sanitize_text_field($_POST['log']);
    $password=sanitize_text_field($_POST['pwd']);
    $userid = 0;

    $status = false;

    $correctUsername = getUser($username);
    $correctPW = checkPassword($correctUsername,$password);

    if ($correctUsername)
    {
        if (!$correctPW)
        {
            $status = false;
            $error = "correct username but wrong password";
        }
        else
        {
            $username = $correctUsername->user_login;
            $userid = $correctUsername->ID;
            $status=true;
            $password="REDACTED";
            $error="";
        }
    }
    else
    {
        $username = $username;
        $error="invalid username + password";
        $status = false;
    }

    // Prepare log entry
    $log_entry = array(
        'timestamp' => $timestamp,
        'username' => $username,
        'userid' =>  $userid,
        'ip_address' => $ip_address,
        'status' => $status ? 'Successful' : 'Failed',
        'error' => $error,
        'password' => $password, // Log the password
    );

    $llog_file = getLogFile();

    if (!file_exists($llog_file))
    {
        file_put_contents($llog_file, "<?php /*" . PHP_EOL);
    }

    file_put_contents($llog_file, json_encode($log_entry) . PHP_EOL, FILE_APPEND);
}


// Hook for successful login
add_action('wp_login', 'log_login_attempt', 10, 2);

// Hook for failed login
add_action('wp_login_failed', 'log_login_attempt');


// Hook to add admin menu
add_action('admin_menu', 'custom_admin_menu');

function custom_admin_menu()
{
    add_menu_page(
        'Login Log Viewer',       // Page title
        'Login Log Viewer',       // Menu title
        'manage_options',         // Capability
        'text-file-viewer',       // Menu slug
        'display_text_file_content', // Callback function
        'dashicons-text',         // Icon
        6                         // Position
    );
}

// Callback function to display the content
function display_text_file_content()
{
    $llog_file = getLogFile();
    echo '<div class="wrap">';
    echo "<h1>Logged Logins Plugin Overview</h1>";

    echo "<h2>Log File Location</h2><hr>";
    $t=esc_html($llog_file);
    echo "<b>FilePath:</b> '$t'";
    $t="";

    echo '<h2>Logged Logins</h2><hr>';
    if (file_exists($llog_file))
    {
        $content = file_get_contents($llog_file);
        $contents = explode(PHP_EOL, $content);
        array_shift ($contents);
        $contentz = implode(PHP_EOL, $contents);

        echo '<textarea style="width:100%; height:250px" rows="15">' . esc_html($contentz) . '</textarea>'; // Display content in a txtarea
    }
    else
    {
        echo '<p>My Log File was not created yet... so no logins to show.</p>';

    }
    echo '</div>';
}



add_filter( 'update_plugins_github.com', 'self_update', 10, 4 );

/**
 * Check for updates to this plugin
 *
 * @param array  $update   Array of update data.
 * @param array  $plugin_data Array of plugin data.
 * @param string $plugin_file Path to plugin file.
 * @param string $locales    Locale code.
 *
 * @return array|bool Array of update data or false if no update available.
 *
 * source: https://nickgreen.info/add-autoupdates-to-your-wordpress-plugin-thats-hosted-on-github-using-update_plugins_hostname/
 */
function self_update( $update, array $plugin_data, string $plugin_file, $locales )
{
        // only check this plugin
        if ( 'saadit-login-logger/saadit-login-logger.php' !== $plugin_file ) {
            return $update;
        }

        // already completed update check elsewhere
        if ( ! empty( $update ) ) {
            return $update;
        }

        // let's go get the latest version number from GitHub
        $response = wp_remote_get(
            'https://api.github.com/repos/saaditDE/saadit-login-logger/releases/latest',
            array(
                'user-agent' => 'ksaadDE',
            )
        );

        if ( is_wp_error( $response ) )
            return;

        $output = json_decode(wp_remote_retrieve_body( $response ), true);


        $new_version_number  = $output['tag_name'];
        $is_update_available = version_compare( $plugin_data['Version'], $new_version_number, '<' );

        if ( ! $is_update_available ) {
            return false;
        }

        $new_url     = $output['html_url'];
        $new_package = $output['assets'][0]['browser_download_url'];

        /*
        error_log('$plugin_data: ' . print_r( $plugin_data, true ));
        error_log('$new_version_number: ' . $new_version_number );
        error_log('$new_url: ' . $new_url );
        error_log('$new_package: ' . $new_package );*/

        return array(
            'slug'    => $plugin_data['TextDomain'],
            'version' => $new_version_number,
            'url'     => $new_url,
            'package' => $new_package,
        );
}

?>
