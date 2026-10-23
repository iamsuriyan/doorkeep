<?php
/**
 * Removes the plugin's data when it is deleted from the Plugins screen:
 * the settings and the doorkeep event IDs stored on comments.
 */
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}
delete_option('doorkeep_settings');
delete_metadata('comment', 0, '_doorkeep_event_id', '', true);
