<?php
/**
 * Plugin Name:     SAAD-IT Login Attempts Logger
 * Description:     Plugin logs invalid or valid wp login attempts via a $log_file, including passwords for invalid attempts
 * Version:         1.7
 * Author:          ksaadDE
 * Author URI:      https://saad-it.de/
 * Update URI:      https://github.com/saaditDE/saadit-login-logger
 */


// Exit if accessed directly
if (!defined('ABSPATH'))
{
    exit;
}

define('LOG_RATE_LIMIT', 7); // 7 second rate limit
define('MAX_TRIES_ROW', 3); // How many attempts are logged in a row, before timeout

define('LOG_MAX_LINES', 500000); // Maximum number of lines to keep
define('LOG_MAX_AGE', 3 * 30 * 24 * 60 * 60); // Maximum age in seconds (3*30 days = roughly 3 months)


// Function to clear old log entries
function clear_old_log_entries($file_path, $max_age)
{
    if (! file_exists ($file_path) )
        return;

    $lines = file($file_path);

    $new_lines = [];

    foreach ($lines as $index => $line)
    {
        if ($index === 0)
        {
            $new_lines[] = $line;
            continue;
        }

        $log_entry = json_decode($line, true);
        if (isset($log_entry['timestamp'])) {
            // Check if the entry is older than max_age
            if (time() - strtotime($log_entry['timestamp']) < $max_age)
            {
                $new_lines[] = $line; // Keep the line if it's within the age limit
            }
        }
    }

    file_put_contents($file_path, implode('', $new_lines));
}


function enforce_line_limit($file_path, $max_lines)
{
    // Check if the file exists
    if (!file_exists($file_path))
        return; // Exit the function if the file does not exist

    // Read the file into an array of lines
    $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    // Check if the number of lines exceeds the limit
    if (count($lines) > $max_lines)
    {
        // Retain the first line
        $first_line = $lines[0];

        // Calculate how many lines to keep from the end
        $lines_to_keep = array_slice($lines, -($max_lines - 1)); // Keep the last (max_lines - 1) lines

        // Combine the first line with the lines to keep
        $lines = array_merge([$first_line], $lines_to_keep);
    }

    // Write the modified lines back to the file
    file_put_contents($file_path, implode(PHP_EOL, $lines) . PHP_EOL);
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
    $current_time = time();

    $last_log_time = get_transient('last_log_time');

    $last_amount = get_transient('last_amount');

    if (($current_time - $last_log_time) <= LOG_RATE_LIMIT)
        return;

    // reset after timeout
    set_transient('last_amount', 0);

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

    // Clear old entries and enforce line limit
    clear_old_log_entries($llog_file, LOG_MAX_AGE);
    enforce_line_limit($llog_file, LOG_MAX_LINES);

    file_put_contents($llog_file, json_encode($log_entry) . PHP_EOL, FILE_APPEND);

    set_transient('last_amount', $last_amount+1); // increase tries that were in a row

    if ($last_amount >= MAX_TRIES_ROW) // if tries in a row exceed the defined max val
        set_transient('last_log_time', $current_time, 12 * HOUR_IN_SECONDS); // Apply timeout
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


    // Clear old entries and enforce line limit
    clear_old_log_entries($llog_file, LOG_MAX_AGE);
    enforce_line_limit($llog_file, LOG_MAX_LINES);

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
