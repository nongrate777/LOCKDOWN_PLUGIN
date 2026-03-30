<?php
/**
 * Plugin Name: Site Access Control
 * Plugin URI:  https://noname.com
 * Description: Управление доступом к фронтенду: открыт / закрыт для людей / закрыт для всех. Администраторы всегда имеют доступ.
 * Version:     1.2.2
 * Author:      VRS Entertainment
 * License:     GPL-2.0
 * Text Domain: site-access-control
 */

defined('ABSPATH') || exit;

// ─────────────────────────────────────────────
//  Константы
// ─────────────────────────────────────────────
define('SAC_VERSION',    '1.2.2');
define('SAC_OPTION_KEY', 'site_access_control_settings');
define('SAC_SLUG',       'site-access-control');

// ─────────────────────────────────────────────
//  Встроенный список ботов
//  Источник: Cloudflare Radar — Search Engine Crawlers + AI Search Bots
//  https://radar.cloudflare.com/bots/directory
// ─────────────────────────────────────────────
function sac_builtin_bots(): array {
    return [
        // ── Search Engine Crawlers (Cloudflare Radar, 44 bots) ──────────
        'Algolia',               // Algolia
        'AllAfricaCrawler',      // All Africa Crawler
        'Baiduspider',           // Baiduspider
        'Baidu-ADS-Proxy',       // Baidu ADS Server Proxy
        'bingbot',               // BingBot
        'Bytespider',            // Toutiao (ByteDance)
        'coccocbot',             // Cốc Cốc
        'CoveoBot',              // Coveo Bot
        'Crawlson',              // Crawlson
        'Daum',                  // Daum
        'DuckDuckBot',           // DuckDuckBot
        'Ecosia',                // Ecosia Bot
        'Exabot',                // Exabot
        'Gigabot',               // Gigabot
        'Googlebot',             // Googlebot
        'Googlebot-Image',       // Googlebot Image
        'Googlebot-Video',       // Googlebot Video
        'Googlebot-News',        // Googlebot News
        'Storebot-Google',       // Googlebot Storebot
        'GoogleOther',           // GoogleOther
        'InfoTigerBot',          // InfoTigerBot
        'Kakaotalk-Scrap',       // KakaoBot
        'LivelapBot',            // LivelapBot
        'MojeekBot',             // MojeekBot
        'NaverBot',              // NaverBot
        'NeevaBot',              // NeevaBot
        'PetalBot',              // PetalBot (Huawei)
        'Qwantify',              // Qwantify
        'Sogou',                 // Sogou Spider
        'SeznamBot',             // SeznamBot
        'SherpaBot',             // SherpaBot
        'SISTRIX',               // SISTRIX Crawler
        'Siteimprove',           // Siteimprove Bot
        'Snapbot',               // Snapbot
        'TurnitinBot',           // TurnitinBot
        'VelenPublicWebCrawler', // VelenPublicWebCrawler
        'Webzio-Extended',       // Webz.io
        'YandexBot',             // YandexBot
        'YisouSpider',           // YisouSpider
        'YoudaoBot',             // YoudaoBot
        'ZoominfoBot',           // ZoominfoBot
        'SeekportBot',           // SeekportBot
        'Swisscows',             // Swisscows Bot
        'Fireball',              // Fireball
        // ── AI Search Bots (Cloudflare Radar, 6 bots) ──────────────────
        'GPTBot',                // OpenAI GPT
        'OAI-SearchBot',         // OpenAI Search
        'Claude-SearchBot',      // Anthropic
        'PerplexityBot',         // Perplexity
        'YouBot',                // You.com
        'Amazonbot',             // Amazon
    ];
}

// ─────────────────────────────────────────────
//  Дефолтные настройки
// ─────────────────────────────────────────────
function sac_defaults(): array {
    return [
        'mode'          => 'open',   // open | bots | closed
        'login_url'     => '',       // кастомный URL логина
        'ip_whitelist'  => '',       // IP через запятую/перенос
        'bots_disabled' => [],       // встроенные боты, которые отключены (массив строк)
        'bots_custom'   => [],       // пользовательские боты (массив строк)
    ];
}

function sac_settings(): array {
    $saved = get_option(SAC_OPTION_KEY, []);
    $merged = wp_parse_args($saved, sac_defaults());
    // wp_parse_args не мержит массивы — гарантируем типы
    if (!is_array($merged['bots_disabled'])) $merged['bots_disabled'] = [];
    if (!is_array($merged['bots_custom']))   $merged['bots_custom']   = [];
    return $merged;
}

// ─────────────────────────────────────────────
//  Итоговый список активных ботов
// ─────────────────────────────────────────────
function sac_allowed_bots(): array {
    $s        = sac_settings();
    $disabled = array_map('strtolower', $s['bots_disabled']);
    $builtin  = array_filter(
        sac_builtin_bots(),
        fn($b) => !in_array(strtolower($b), $disabled, true)
    );
    $custom   = array_filter($s['bots_custom'], fn($b) => $b !== '');
    return apply_filters('sac_allowed_bots', array_values(array_merge($builtin, $custom)));
}

// ─────────────────────────────────────────────
//  Хелперы проверки
// ─────────────────────────────────────────────
function sac_is_allowed_bot(): bool {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ($ua === '') return false;
    foreach (sac_allowed_bots() as $bot) {
        if (stripos($ua, $bot) !== false) return true;
    }
    return false;
}

function sac_is_whitelisted_ip(): bool {
    $s   = sac_settings();
    $raw = $s['ip_whitelist'] ?? '';
    if ($raw === '') return false;
    $list    = preg_split('/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY);
    $visitor = $_SERVER['REMOTE_ADDR'] ?? '';
    return in_array($visitor, $list, true);
}

function sac_login_url(): string {
    $s = sac_settings();
    if (!empty($s['login_url'])) {
        return '/' . ltrim($s['login_url'], '/');
    }
    if (function_exists('wps_hide_login_url')) {
        $url = wps_hide_login_url();
        return '/' . ltrim(wp_parse_url($url, PHP_URL_PATH), '/');
    }
    if (class_exists('AIO_WP_Security') || defined('AIOWPSEC_ADMIN_MENU_SLUG')) {
        $slug = get_option('aiowps_login_page_slug', '');
        if ($slug) return '/' . ltrim($slug, '/');
    }
    return '/wp-login.php';
}

// ─────────────────────────────────────────────
//  Основная логика блокировки
// ─────────────────────────────────────────────
add_action('wp', function () {
    if (defined('WP_CLI') && WP_CLI) return;

    $s    = sac_settings();
    $mode = $s['mode'] ?? 'open';
    if ($mode === 'open') return;

    $uri    = $_SERVER['REQUEST_URI'] ?? '/';
    $path   = '/' . ltrim(parse_url($uri, PHP_URL_PATH) ?: '/', '/');
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

    if (
        stripos($path, '/wp-admin') === 0 ||
        stripos($path, '/wp-cron.php') === 0 ||
        stripos($path, '/wp-json') === 0
    ) return;

    $login_path = sac_login_url();
    if ($path === $login_path || stripos($path, '/wp-login.php') === 0) return;

    if (is_user_logged_in())    return;
    if (sac_is_whitelisted_ip()) return;
    if ($mode === 'bots' && sac_is_allowed_bot()) return;

    sac_render_403();
}, 0);

// ─────────────────────────────────────────────
//  Редирект кастомного slug → wp-login.php
// ─────────────────────────────────────────────
add_action('template_redirect', function () {
    $login_path = sac_login_url();
    $uri  = $_SERVER['REQUEST_URI'] ?? '/';
    $path = '/' . ltrim(parse_url($uri, PHP_URL_PATH) ?: '/', '/');

    if ($path !== $login_path || $login_path === '/wp-login.php') return;

    $_SERVER['REQUEST_URI'] = '/wp-login.php';
    $_SERVER['PHP_SELF']    = '/wp-login.php';
    $_SERVER['SCRIPT_NAME'] = '/wp-login.php';
    $GLOBALS['pagenow']     = 'wp-login.php';

    require ABSPATH . 'wp-login.php';
    exit;
}, 0);

// ─────────────────────────────────────────────
//  403-страница
// ─────────────────────────────────────────────
function sac_render_403(): void {
    if (!headers_sent()) {
        status_header(403);
        header('Content-Type: text/html; charset=UTF-8', true, 403);
        header('X-Robots-Tag: noindex, nofollow', true);
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0', true);
        header('Pragma: no-cache', true);
    }
    echo '""';
    exit;
}

// ─────────────────────────────────────────────
//  Страница настроек
// ─────────────────────────────────────────────
add_action('admin_menu', function () {
    add_options_page(
        'Site Access Control', 'Site Access Control',
        'manage_options', SAC_SLUG, 'sac_render_settings_page'
    );
});

add_action('admin_init', function () {
    register_setting(SAC_OPTION_KEY, SAC_OPTION_KEY, [
        'sanitize_callback' => 'sac_sanitize_settings',
    ]);
});

function sac_sanitize_settings($input): array {
    if (!is_array($input)) $input = [];

    $mode = in_array($input['mode'] ?? '', ['open', 'bots', 'closed'], true)
        ? $input['mode'] : 'open';

    $login_url    = trim(sanitize_text_field($input['login_url'] ?? ''), '/');
    $ip_whitelist = sanitize_textarea_field($input['ip_whitelist'] ?? '');

    // Отключённые встроенные боты — только те что реально существуют в builtin
    $builtin_keys  = sac_builtin_bots();
    $raw_disabled  = is_array($input['bots_disabled'] ?? null) ? $input['bots_disabled'] : [];
    $bots_disabled = array_values(array_intersect($builtin_keys, $raw_disabled));

    // Кастомные боты
    $raw_custom  = sanitize_textarea_field($input['bots_custom_raw'] ?? '');
    $bots_custom = array_values(array_filter(
        array_map('sanitize_text_field', preg_split('/[\r\n,]+/', $raw_custom, -1, PREG_SPLIT_NO_EMPTY)),
        fn($b) => $b !== ''
    ));

    return compact('mode', 'login_url', 'ip_whitelist', 'bots_disabled', 'bots_custom');
}

function sac_render_settings_page(): void {
    if (!current_user_can('manage_options')) wp_die('Access denied.');

    $s     = sac_settings();
    $saved = !empty($_GET['settings-updated']);

    $disabled_list = $s['bots_disabled'];
    $custom_list   = $s['bots_custom'];
    $custom_raw    = implode("\n", $custom_list);
    ?>
    <div class="wrap">
        <h1>Site Access Control</h1>

        <?php if ($saved): ?>
            <div class="notice notice-success is-dismissible"><p>Настройки сохранены.</p></div>
        <?php endif; ?>

        <style>
            .sac-bots-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                gap: 6px 16px;
                margin-top: 8px;
            }
            .sac-bots-grid label { display: flex; align-items: center; gap: 6px; cursor: pointer; }
            .sac-bots-grid label.disabled-bot { opacity: .45; text-decoration: line-through; }
            .sac-login-hint { color: #cc0000; font-weight: 600; }
        </style>

        <form method="post" action="options.php">
            <?php settings_fields(SAC_OPTION_KEY); ?>

            <table class="form-table" role="presentation">

                <!-- Режим работы -->
                <tr>
                    <th scope="row">Режим работы</th>
                    <td>
                        <fieldset>
                            <label>
                                <input type="radio" name="<?= SAC_OPTION_KEY ?>[mode]"
                                       value="open" <?php checked($s['mode'], 'open') ?>>
                                <strong>Открыт</strong> — обычная работа без ограничений
                            </label><br><br>
                            <label>
                                <input type="radio" name="<?= SAC_OPTION_KEY ?>[mode]"
                                       value="bots" <?php checked($s['mode'], 'bots') ?>>
                                <strong>Закрыт для людей, открыт для ботов</strong> —
                                403 для обычных посетителей, поисковые и AI-боты проходят свободно
                            </label><br><br>
                            <label>
                                <input type="radio" name="<?= SAC_OPTION_KEY ?>[mode]"
                                       value="closed" <?php checked($s['mode'], 'closed') ?>>
                                <strong>Полностью закрыт</strong> — 403 для всех, включая ботов
                            </label>
                        </fieldset>
                    </td>
                </tr>

                <!-- URL логина -->
                <tr>
                    <th scope="row"><label for="sac_login_url">URL логина</label></th>
                    <td>
                        <input
                                type="text"
                                id="sac_login_url"
                                name="<?= SAC_OPTION_KEY ?>[login_url]"
                                value="<?= esc_attr($s['login_url']) ?>"
                                class="regular-text"
                                placeholder="my-secret-login"
                        >
                        <p class="description sac-login-hint" style="color: red;">
                            Слаг добавляем вручную
                        </p>
                    </td>
                </tr>

                <!-- IP-вайтлист -->
                <tr>
                    <th scope="row"><label for="sac_ip_whitelist">IP-вайтлист</label></th>
                    <td>
                        <textarea
                                id="sac_ip_whitelist"
                                name="<?= SAC_OPTION_KEY ?>[ip_whitelist]"
                                rows="4"
                                class="large-text"
                                placeholder="192.168.1.1&#10;10.0.0.2"
                        ><?= esc_textarea($s['ip_whitelist']) ?></textarea>
                        <p class="description">IP-адреса через запятую или с новой строки. Всегда имеют доступ.</p>
                    </td>
                </tr>

            </table>

            <!-- ── Управление ботами ───────────────────────────────── -->
            <hr style="margin:24px 0 20px">
            <h2>Список ботов</h2>
            <p style="margin-bottom:12px;">
                Используется только в режиме «Закрыт для людей, открыт для ботов».<br>
                <strong>Активируйте чекбокс</strong> — бот будет заблокирован.
            </p>

            <h3 style="margin-bottom:8px;">Встроенные боты
                <span style="font-weight:400;font-size:13px;color:#666;">
                    (Cloudflare Radar: Search Engine Crawlers + AI Search Bots)
                </span>
            </h3>
            <div class="sac-bots-grid">
                <?php foreach (sac_builtin_bots() as $bot):
                    $is_disabled = in_array($bot, $disabled_list, true);
                    ?>
                    <label class="<?= $is_disabled ? 'disabled-bot' : '' ?>">
                        <input
                                type="checkbox"
                                name="<?= SAC_OPTION_KEY ?>[bots_disabled][]"
                                value="<?= esc_attr($bot) ?>"
                            <?php checked($is_disabled) ?>
                                onchange="this.closest('label').classList.toggle('disabled-bot', this.checked)"
                        >
                        <code><?= esc_html($bot) ?></code>
                    </label>
                <?php endforeach; ?>
            </div>

            <p style="margin-top:6px;color:#888;font-size:12px;">
                ☑ = бот отключён (заблокирован) &nbsp;|&nbsp; ☐ = бот активен (проходит)
            </p>

            <h3 style="margin:20px 0 8px;">Дополнительные боты</h3>
            <textarea
                    name="<?= SAC_OPTION_KEY ?>[bots_custom_raw]"
                    rows="4"
                    class="large-text"
                    placeholder="MyBot&#10;AnotherCrawler"
            ><?= esc_textarea($custom_raw) ?></textarea>
            <p class="description">
                Один User-Agent на строку (или через запятую). Добавляются к списку выше.
            </p>

            <?php submit_button('Сохранить настройки'); ?>
        </form>
    </div>
    <?php
}

// ─────────────────────────────────────────────
//  Ссылка «Настройки» на странице плагинов
// ─────────────────────────────────────────────
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function (array $links): array {
    $url = admin_url('options-general.php?page=' . SAC_SLUG);
    array_unshift($links, '<a href="' . esc_url($url) . '">Настройки</a>');
    return $links;
});



// ─────────────────────────────────────────────
//  AUTO-UPDATE FROM GITHUB
//  update.json лежит в корне репозитория
// ─────────────────────────────────────────────

define('SAC_UPDATE_URL', 'https://raw.githubusercontent.com/nongrate777/LOCKDOWN_PLUGIN/master/update.json');
define('SAC_PLUGIN_FILE', plugin_basename(__FILE__)); // site-access-control/site-access-control.php

add_filter('pre_set_site_transient_update_plugins', 'sac_check_for_update');
function sac_check_for_update(object $transient): object {
    if (empty($transient->checked)) return $transient;

    $remote = sac_get_remote_update_info();
    if (!$remote) return $transient;

    $installed = $transient->checked[SAC_PLUGIN_FILE] ?? '0';

    if (version_compare($remote->version, $installed, '>')) {
        $transient->response[SAC_PLUGIN_FILE] = (object) [
            'slug'        => 'site-access-control',
            'plugin'      => SAC_PLUGIN_FILE,
            'new_version' => $remote->version,
            'url'         => $remote->details_url,
            'package'     => $remote->download_url,
        ];
    }

    return $transient;
}

// Подставляем инфо на странице «View details»
add_filter('plugins_api', 'sac_plugin_info', 10, 3);
function sac_plugin_info(mixed $result, string $action, object $args): mixed {
    if ($action !== 'plugin_information') return $result;
    if (!isset($args->slug) || $args->slug !== 'site-access-control') return $result;

    $remote = sac_get_remote_update_info();
    if (!$remote) return $result;

    return (object) [
        'name'          => 'Site Access Control',
        'slug'          => 'site-access-control',
        'version'       => $remote->version,
        'author'        => 'VRS Entertainment',
        'homepage'      => $remote->details_url,
        'download_link' => $remote->download_url,
        'sections'      => [
            'description' => 'Управление доступом к фронтенду WordPress.',
            'changelog'   => $remote->changelog ?? '',
        ],
    ];
}

// Получаем update.json с GitHub (кешируем на 12 часов)
function sac_get_remote_update_info(): ?object {
    $cache_key = 'sac_update_info';
    $cached    = get_transient($cache_key);
    if ($cached !== false) return $cached;

    $response = wp_remote_get(SAC_UPDATE_URL, [
        'timeout' => 10,
        'headers' => ['Accept' => 'application/json'],
    ]);

    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        set_transient($cache_key, null, HOUR_IN_SECONDS);
        return null;
    }

    $data = json_decode(wp_remote_retrieve_body($response));
    if (empty($data->version) || empty($data->download_url)) {
        set_transient($cache_key, null, HOUR_IN_SECONDS);
        return null;
    }

    set_transient($cache_key, $data, 12 * HOUR_IN_SECONDS);
    return $data;
}