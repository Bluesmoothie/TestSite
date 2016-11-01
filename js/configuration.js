jQuery(function ($) {
    var download_button = $('#configuration-download');

    // Create a blob object.
    var bb = new Blob(
        ["---\naudit:\n  parameter_values: true\n  exclude_vector_patterns: []\n  include_vector_patterns: []\n  link_templates: []\n  links: true\n  forms: true\n  cookies: true\n  headers: false\n  with_both_http_methods: false\n  cookies_extensively: false\n  jsons: true\n  xmls: true\n  ui_forms: true\n  ui_inputs: true\nbrowser_cluster:\n  local_storage: {}\n  wait_for_elements: {}\n  pool_size: 6\n  job_timeout: 25\n  worker_time_to_live: 100\n  ignore_images: false\n  screen_width: 1600\n  screen_height: 1200\ndatastore:\n  token: 0748b2423a1a24f003a16c72c553fe18\nhttp:\n  user_agent: Arachni/v1.4\n  request_timeout: 10000\n  request_redirect_limit: 5\n  request_concurrency: 20\n  request_queue_size: 100\n  request_headers: {}\n  response_max_size: 500000\n  cookies: {}\ninput:\n  values: {}\n  default_values:\n    name: arachni_name\n    user: arachni_user\n    usr: arachni_user\n    pass: 5543!%arachni_secret\n    txt: arachni_text\n    num: '132'\n    amount: '100'\n    mail: arachni@email.gr\n    account: '12'\n    id: '1'\n  without_defaults: true\n  force: false\nscope:\n  redundant_path_patterns: {}\n  dom_depth_limit: 5\n  exclude_file_extensions: []\n  exclude_path_patterns: []\n  exclude_content_patterns: []\n  include_path_patterns: []\n  restrict_paths: []\n  extend_paths: []\n  url_rewrites: {}\n  include_subdomains: false\n  exclude_binaries: false\n  https_only: false\nsession: {}\nchecks:\n- code_injection\n- code_injection_php_input_wrapper\n- code_injection_timing\n- csrf\n- file_inclusion\n- ldap_injection\n- no_sql_injection\n- no_sql_injection_differential\n- os_cmd_injection\n- os_cmd_injection_timing\n- path_traversal\n- response_splitting\n- rfi\n- session_fixation\n- source_code_disclosure\n- sql_injection\n- sql_injection_differential\n- sql_injection_timing\n- trainer\n- unvalidated_redirect\n- unvalidated_redirect_dom\n- xpath_injection\n- xss\n- xss_dom\n- xss_dom_script_context\n- xss_event\n- xss_path\n- xss_script_context\n- xss_tag\n- xxe\n- allowed_methods\n- backdoors\n- backup_directories\n- backup_files\n- captcha\n- common_admin_interfaces\n- common_directories\n- common_files\n- cookie_set_for_parent_domain\n- credit_card\n- cvs_svn_users\n- directory_listing\n- emails\n- form_upload\n- hsts\n- htaccess_limit\n- html_objects\n- http_only_cookies\n- http_put\n- insecure_client_access_policy\n- insecure_cookies\n- insecure_cors_policy\n- insecure_cross_domain_policy_access\n- insecure_cross_domain_policy_headers\n- interesting_responses\n- localstart_asp\n- mixed_resource\n- origin_spoof_access_restriction_bypass\n- password_autocomplete\n- private_ip\n- ssn\n- unencrypted_password_forms\n- webdav\n- x_frame_options\n- xst\nplatforms: []\nplugins: {}\nno_fingerprinting: false\nauthorized_by: \nurl: http://bangestion.isolonice.fr/\n"],
        { type : 'application/yaml' }
    );

    download_button.attr( 'href', window.URL.createObjectURL( bb ) );
    download_button.attr( 'download', 'bangestion.isolonice.fr-profile.afp' );
});
