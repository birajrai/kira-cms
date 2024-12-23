<?php
/**
 * Kira CMS functions and API restrictions with improved CORS handling
 * and endpoint security
 */

// Block direct access to REST API endpoints
function kira_cms_rest_authentication($result) {
    // If already authenticated, return the result
    if (true === $result || is_wp_error($result)) {
        return $result;
    }

    // Get the request URI and origin
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // Block if accessing wp-json endpoints directly without proper CORS
    if (strpos($request_uri, '/wp-json') !== false && empty($origin)) {
        return new WP_Error(
            'rest_forbidden',
            'Direct access to REST API is not allowed.',
            ['status' => 403]
        );
    }

    // If there's an origin, validate it
    if (!empty($origin)) {
        $allowed_domains = get_site_option('kira_cms_allowed_domains', '');
        $allowed_domains_array = array_filter(array_map('trim', explode("\n", $allowed_domains)));

        if (!kira_cms_is_origin_allowed($origin, $allowed_domains_array)) {
            return new WP_Error(
                'rest_forbidden',
                'Access denied due to invalid origin.',
                ['status' => 403]
            );
        }
    }

    return $result;
}
add_filter('rest_authentication_errors', 'kira_cms_rest_authentication', 99);

// Register Admin Menu
function kira_cms_register_menu_page() {
    $hook_name = is_multisite() ? 'network_admin_menu' : 'admin_menu';
    add_action($hook_name, function() {
        add_menu_page(
            'Allowed API Domains',
            'API Domains',
            'manage_options',
            'kira-cms-api-domains',
            'kira_cms_render_menu_page',
            'dashicons-admin-network',
            90
        );
    });
}
add_action('init', 'kira_cms_register_menu_page');

// Render Admin Menu Page
function kira_cms_render_menu_page() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['allowed_domains']) && check_admin_referer('kira_cms_update_domains')) {
        $allowed_domains = sanitize_textarea_field($_POST['allowed_domains']);
        update_site_option('kira_cms_allowed_domains', $allowed_domains);
        echo '<div class="updated"><p>Allowed domains updated successfully.</p></div>';
    }

    $allowed_domains = get_site_option('kira_cms_allowed_domains', '');
    ?>
    <div class="wrap">
        <h1>Allowed API Domains</h1>
        <form method="POST">
            <?php wp_nonce_field('kira_cms_update_domains'); ?>
            <textarea name="allowed_domains" rows="10" cols="50" class="large-text"><?php echo esc_textarea($allowed_domains); ?></textarea>
            <p>Enter one domain per line. Wildcards are supported. Examples:</p>
            <ul>
                <li>example.com</li>
                <li>*.example.com</li>
                <li>subdomain.example.com</li>
            </ul>
            <input type="submit" class="button-primary" value="Save Changes">
        </form>
    </div>
    <?php
}

// Improved Origin Validation
function kira_cms_is_origin_allowed($origin, $allowed_domains) {
    // Normalize the origin by removing protocol and any trailing slash
    $normalized_origin = preg_replace('#^https?://#', '', rtrim($origin, '/'));

    foreach ($allowed_domains as $domain) {
        $domain = trim($domain);
        if (empty($domain)) continue;

        // Normalize the allowed domain
        $domain = preg_replace('#^https?://#', '', rtrim($domain, '/'));

        // Exact match check
        if ($normalized_origin === $domain) {
            return true;
        }

        // Wildcard check
        if (strpos($domain, '*.') === 0) {
            $wildcard_pattern = str_replace('*.', '', $domain);
            if (preg_match('/^.+\.' . preg_quote($wildcard_pattern, '/') . '$/', $normalized_origin)) {
                return true;
            }
        }
    }

    return false;
}

// Improved CORS Headers Handler
function kira_cms_set_cors_headers($result) {
    // Handle preflight requests
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With');
        header('Access-Control-Max-Age: 86400'); // 24 hours cache
        exit(0);
    }

    if (isset($_SERVER['HTTP_ORIGIN'])) {
        $origin = $_SERVER['HTTP_ORIGIN'];
        $allowed_domains = get_site_option('kira_cms_allowed_domains', '');
        $allowed_domains_array = array_filter(array_map('trim', explode("\n", $allowed_domains)));

        if (kira_cms_is_origin_allowed($origin, $allowed_domains_array)) {
            header('Access-Control-Allow-Origin: ' . $origin);
            header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
            header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With');
            header('Access-Control-Allow-Credentials: true');
            header('Vary: Origin'); // Important for caching
        } else {
            header('HTTP/1.1 403 Forbidden');
            echo json_encode([
                'code' => 'rest_forbidden',
                'message' => 'CORS policy error: Origin not allowed',
                'data' => [
                    'status' => 403,
                    'origin' => $origin
                ]
            ]);
            exit;
        }
    }

    return $result;
}

// Add CORS headers early and remove default WordPress CORS
add_action('rest_api_init', function() {
    remove_filter('rest_pre_serve_request', 'rest_send_cors_headers');
    add_filter('rest_pre_serve_request', 'kira_cms_set_cors_headers', 0);
}, 15);

// Disable REST API root discovery
remove_action('template_redirect', 'rest_output_link_header', 11);
remove_action('wp_head', 'rest_output_link_wp_head', 10);

// Optional debugging
if (defined('KIRA_CMS_DEBUG') && KIRA_CMS_DEBUG) {
    function kira_cms_debug_cors() {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? 'None';
        $allowed_domains = get_site_option('kira_cms_allowed_domains', '');
        error_log('CORS Debug - Origin: ' . $origin);
        error_log('CORS Debug - Allowed Domains: ' . $allowed_domains);
        error_log('CORS Debug - Request Method: ' . $_SERVER['REQUEST_METHOD']);
        error_log('CORS Debug - Headers: ' . print_r(getallheaders(), true));
    }
    add_action('rest_api_init', 'kira_cms_debug_cors');
}