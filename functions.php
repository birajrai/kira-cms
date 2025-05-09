<?php
/**
 * Kira CMS functions
 */

// Redirect root URL to https://www.meropatra.com
add_action('template_redirect', function () {
    if (is_front_page() && !is_admin()) {
        wp_redirect('https://www.meropatra.com');
        exit;
    }
});
