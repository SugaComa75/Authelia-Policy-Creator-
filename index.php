<?php
// Authelia Policy Builder - simple standalone PHP tool
// This tool generates YAML only. It does not validate Authelia configuration.

// Allowed policies for basic sanitisation.
$allowed_policies = ['deny', 'bypass', 'one_factor', 'two_factor'];

// Helper: escape double quotes for YAML safety.
function escape_quotes($str) {
    return str_replace('"', '\"', trim($str));
}

// Helper: escape a path segment for safe regex output.
function regex_escape_path($path) {
    return preg_quote($path, '/');
}

// Helper: turn a friendly keyword/path into an Authelia resource regex.
//
// Supported input styles:
//   cloud                 -> ^/cloud([/?].*)?$
//   /cloud                -> ^/cloud([/?].*)?$
//   /cloud/admin          -> ^/cloud/admin([/?].*)?$
//   regex:^/admin.*$      -> ^/admin.*$
//   ^/admin.*$            -> ^/admin.*$
//
// This keeps the form easy for beginners but still allows advanced users to paste raw regex.
function normalise_resource_rule($raw) {
    $value = trim($raw);

    if ($value === '') {
        return '';
    }

    // Advanced mode: allow explicit raw regex.
    if (stripos($value, 'regex:') === 0) {
        return trim(substr($value, 6));
    }

    // If it already looks like a regex, keep it as provided.
    if (substr($value, 0, 1) === '^') {
        return $value;
    }

    // Remove accidental protocol/domain if someone pastes a full URL.
    $parts = parse_url($value);
    if (is_array($parts) && isset($parts['path']) && $parts['path'] !== '') {
        $value = $parts['path'];
    }

    // Convert simple keywords/paths into a safe path regex.
    $value = trim($value);
    $value = trim($value, " \t\n\r\0\x0B/");
    if ($value === '') {
        return '^/([/?].*)?$';
    }

    $segments = array_filter(explode('/', $value), function ($segment) {
        return trim($segment) !== '';
    });

    $safe_segments = array_map('regex_escape_path', $segments);
    $safe_path = implode('\/', $safe_segments);

    return '^/' . $safe_path . '([/?].*)?$';
}

// Helper: build subject lines from comma-separated users/groups.
function build_subject_block($users_raw, $groups_raw) {
    $subjects = [];

    if (!empty($users_raw)) {
        $users = array_filter(array_map('trim', explode(',', $users_raw)));
        foreach ($users as $user) {
            $user = preg_replace('/^user:/i', '', $user);
            if ($user !== '') {
                $subjects[] = '- "user:' . escape_quotes($user) . '"';
            }
        }
    }

    if (!empty($groups_raw)) {
        $groups = array_filter(array_map('trim', explode(',', $groups_raw)));
        foreach ($groups as $group) {
            $group = preg_replace('/^group:/i', '', $group);
            if ($group !== '') {
                $subjects[] = '- "group:' . escape_quotes($group) . '"';
            }
        }
    }

    if (count($subjects) === 0) {
        return '';
    }

    $block = "      subject:\n";
    foreach ($subjects as $line) {
        $block .= "        " . $line . "\n";
    }

    return $block;
}

// Helper: build resources block from one-per-line keyword/path/regex input.
function build_resources_block($resources_raw) {
    if (empty($resources_raw)) {
        return '';
    }

    $lines = preg_split('/\r\n|\r|\n/', $resources_raw);
    $lines = array_filter(array_map('trim', $lines));

    if (count($lines) === 0) {
        return '';
    }

    $block = "      resources:\n";
    foreach ($lines as $res) {
        $generated = normalise_resource_rule($res);
        if ($generated !== '') {
            $block .= '        - "' . escape_quotes($generated) . '"' . "\n";
        }
    }

    return $block;
}

// Helper: priority-sort rules so Authelia evaluates them safely.
// Authelia uses the first matching rule, so resource/path restrictions must come before broad access rules.
function rule_priority($rule) {
    $domain = $rule['domain'] ?? '';
    $policy = $rule['policy'] ?? 'deny';
    $has_resources = trim($rule['resources'] ?? '') !== '';
    $is_wildcard = strpos($domain, '*') !== false;

    if ($has_resources) {
        return 10; // Most specific: folder/path/resource rules.
    }

    if ($is_wildcard) {
        return 40; // Catch-all/wildcard rules last.
    }

    if ($policy === 'bypass') {
        return 30; // Public exact-domain rules after protected exact-domain rules.
    }

    return 20; // Exact protected/deny rules.
}

// Generate YAML if form submitted.
$yaml_output = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $default_policy = isset($_POST['default_policy']) ? trim($_POST['default_policy']) : 'deny';
    if (!in_array($default_policy, $allowed_policies, true)) {
        $default_policy = 'deny';
    }

    $rules = [];

    if (isset($_POST['domain']) && is_array($_POST['domain'])) {
        $domains       = $_POST['domain'];
        $policies      = $_POST['policy'] ?? [];
        $users_arr     = $_POST['users'] ?? [];
        $groups_arr    = $_POST['groups'] ?? [];
        $resources_arr = $_POST['resources'] ?? [];

        for ($i = 0; $i < count($domains); $i++) {
            $domain = trim($domains[$i] ?? '');

            if ($domain === '') {
                continue;
            }

            $policy = isset($policies[$i]) ? trim($policies[$i]) : 'deny';
            if (!in_array($policy, $allowed_policies, true)) {
                $policy = 'deny';
            }

            $rules[] = [
                'domain'    => $domain,
                'policy'    => $policy,
                'users'     => $users_arr[$i] ?? '',
                'groups'    => $groups_arr[$i] ?? '',
                'resources' => $resources_arr[$i] ?? '',
                'original'   => $i,
            ];
        }
    }

    usort($rules, function ($a, $b) {
        $priority = rule_priority($a) <=> rule_priority($b);
        if ($priority !== 0) {
            return $priority;
        }

        // Keep original order inside each priority group.
        return ($a['original'] ?? 0) <=> ($b['original'] ?? 0);
    });

    $yaml = "access_control:\n";
    $yaml .= "  default_policy: " . $default_policy . "\n\n";
    $yaml .= "  rules:\n";

    foreach ($rules as $rule) {
        $yaml .= '    - domain: "' . escape_quotes($rule['domain']) . '"' . "\n";

        $resources_block = build_resources_block($rule['resources']);
        if ($resources_block !== '') {
            $yaml .= $resources_block;
        }

        $yaml .= "      policy: " . $rule['policy'] . "\n";

        $subject_block = build_subject_block($rule['users'], $rule['groups']);
        if ($subject_block !== '') {
            $yaml .= $subject_block;
        }

        $yaml .= "\n";
    }

    $yaml_output = trim($yaml) . "\n";
}

// Helper for repopulating form values.
function post_value($array_name, $index, $default = '') {
    return htmlspecialchars($_POST[$array_name][$index] ?? $default, ENT_QUOTES);
}

function selected_policy($current, $value) {
    return $current === $value ? 'selected' : '';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Authelia Policy Builder</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="page">
    <header class="header">
        <h1>Authelia Policy Builder</h1>
        <p>A simple local PHP tool to generate <code>access_control</code> YAML rules for Authelia.</p>
        <p class="warning">
            ⚠️ This tool does <strong>not</strong> validate your Authelia configuration.
            Always test the generated YAML with Authelia before using it in production.
        </p>
    </header>

    <main>
        <section class="card">
            <h2>Default Policy</h2>
            <form method="post" id="policyForm">
                <div class="form-row">
                    <label for="default_policy">Default policy:</label>
                    <select name="default_policy" id="default_policy">
                        <?php $current_default = $_POST['default_policy'] ?? 'deny'; ?>
                        <option value="deny" <?php echo selected_policy($current_default, 'deny'); ?>>deny</option>
                        <option value="bypass" <?php echo selected_policy($current_default, 'bypass'); ?>>bypass</option>
                        <option value="one_factor" <?php echo selected_policy($current_default, 'one_factor'); ?>>one_factor</option>
                        <option value="two_factor" <?php echo selected_policy($current_default, 'two_factor'); ?>>two_factor</option>
                    </select>
                </div>

                <h2>Access-Control Rules</h2>
                <p class="hint">
                    Add rules from most specific to most general. The generator will also sort them safely:
                    resource/path rules first, exact protected domains next, public bypass rules after that, and wildcard rules last.
                </p>

                <div class="order-guide">
                    <strong>Recommended order:</strong>
                    <span>1. Protected folders/resources</span>
                    <span>2. Protected subdomains</span>
                    <span>3. Public exact domains</span>
                    <span>4. Wildcards/catch-all rules</span>
                </div>

                <div id="rulesContainer">
                    <?php
                    $rule_count = ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domain']) && is_array($_POST['domain']))
                        ? count($_POST['domain'])
                        : 1;

                    for ($i = 0; $i < $rule_count; $i++) {
                        $domain_val    = post_value('domain', $i, $i === 0 ? 'kitchen.example.com' : '');
                        $policy_val    = $_POST['policy'][$i] ?? 'one_factor';
                        $users_val     = post_value('users', $i);
                        $groups_val    = post_value('groups', $i, $i === 0 ? 'Family' : '');
                        $resources_val = post_value('resources', $i);
                        ?>
                        <div class="rule-card">
                            <div class="rule-header">
                                <span>Rule</span>
                                <button type="button" class="remove-rule" onclick="removeRule(this)">Remove</button>
                            </div>
                            <div class="form-row">
                                <label>Domain:</label>
                                <input type="text" name="domain[]" placeholder="kitchen.example.com or *.example.com" value="<?php echo $domain_val; ?>">
                            </div>
                            <div class="form-row">
                                <label>Policy:</label>
                                <select name="policy[]">
                                    <option value="deny" <?php echo selected_policy($policy_val, 'deny'); ?>>deny</option>
                                    <option value="bypass" <?php echo selected_policy($policy_val, 'bypass'); ?>>bypass</option>
                                    <option value="one_factor" <?php echo selected_policy($policy_val, 'one_factor'); ?>>one_factor</option>
                                    <option value="two_factor" <?php echo selected_policy($policy_val, 'two_factor'); ?>>two_factor</option>
                                </select>
                            </div>
                            <div class="form-row">
                                <label>Users (comma-separated):</label>
                                <input type="text" name="users[]" placeholder="alice, bob" value="<?php echo $users_val; ?>">
                            </div>
                            <div class="form-row">
                                <label>Groups (comma-separated):</label>
                                <input type="text" name="groups[]" placeholder="Family, Admin" value="<?php echo $groups_val; ?>">
                            </div>
                            <div class="form-row">
                                <label>Resources / paths / keywords (one per line):</label>
                                <textarea name="resources[]" rows="4" placeholder="cloud&#10;/admin&#10;regex:^/custom.*$"><?php echo $resources_val; ?></textarea>
                                <small class="field-help">
                                    Enter <code>cloud</code> or <code>/cloud</code> to generate <code>^/cloud([/?].*)?$</code>.
                                    Use <code>regex:</code> or start with <code>^</code> to keep raw regex.
                                </small>
                            </div>
                        </div>
                        <?php
                    }
                    ?>
                </div>

                <div class="actions">
                    <button type="button" class="btn secondary" onclick="addRule()">Add Rule</button>
                    <button type="submit" class="btn primary">Generate YAML</button>
                    <button type="button" class="btn" onclick="clearForm()">Clear Form</button>
                </div>
            </form>
        </section>

        <section class="card">
            <h2>Generated YAML</h2>
            <p class="hint">
                Copy this into your Authelia configuration under the <code>access_control</code> section.
            </p>
            <textarea id="yamlOutput" rows="18" readonly><?php echo htmlspecialchars($yaml_output, ENT_QUOTES); ?></textarea>
            <div class="actions">
                <button type="button" class="btn primary" onclick="copyYaml()">Copy YAML</button>
            </div>
        </section>

        <section class="card">
            <h2>Help</h2>
            <ul class="help-list">
                <li><strong>bypass</strong> – no login required.</li>
                <li><strong>deny</strong> – blocks access.</li>
                <li><strong>one_factor</strong> – requires login.</li>
                <li><strong>two_factor</strong> – requires login plus 2FA.</li>
                <li><strong>resources</strong> – regex path matches. Friendly inputs such as <code>cloud</code> are converted automatically.</li>
            </ul>

            <h3>Rule order</h3>
            <p class="hint">
                Authelia uses the first matching rule. Put restrictions first, then broader access rules.
                This tool sorts generated rules in that order to reduce mistakes.
            </p>

<pre>
1. Protected folders/resources
2. Protected exact subdomains
3. Public exact-domain bypass rules
4. Wildcard/catch-all rules
</pre>

            <h3>Resource keyword examples</h3>
<pre>
cloud        becomes "^/cloud([/?].*)?$"
/admin       becomes "^/admin([/?].*)?$"
/cloud/docs  becomes "^/cloud/docs([/?].*)?$"
regex:^/x.*$ keeps "^/x.*$"
^/raw.*$     keeps "^/raw.*$"
</pre>

            <p class="hint">
                Groups should be entered without <code>group:</code> (e.g. <code>Family, Admin</code>) and will be output as:
            </p>
<pre>
subject:
  - "group:Family"
  - "group:Admin"
</pre>
            <p class="hint">
                Users should be entered without <code>user:</code> (e.g. <code>alice, bob</code>) and will be output as:
            </p>
<pre>
subject:
  - "user:alice"
  - "user:bob"
</pre>
            <p class="warning">
                Always test the generated YAML with Authelia to ensure it behaves as expected.
            </p>
        </section>
    </main>
</div>

<script>
// Template for a new rule card.
function createRuleCard() {
    const container = document.createElement('div');
    container.className = 'rule-card';
    container.innerHTML = `
        <div class="rule-header">
            <span>Rule</span>
            <button type="button" class="remove-rule" onclick="removeRule(this)">Remove</button>
        </div>
        <div class="form-row">
            <label>Domain:</label>
            <input type="text" name="domain[]" placeholder="admin.example.com or *.example.com">
        </div>
        <div class="form-row">
            <label>Policy:</label>
            <select name="policy[]">
                <option value="deny">deny</option>
                <option value="bypass">bypass</option>
                <option value="one_factor" selected>one_factor</option>
                <option value="two_factor">two_factor</option>
            </select>
        </div>
        <div class="form-row">
            <label>Users (comma-separated):</label>
            <input type="text" name="users[]" placeholder="alice, bob">
        </div>
        <div class="form-row">
            <label>Groups (comma-separated):</label>
            <input type="text" name="groups[]" placeholder="Family, Admin">
        </div>
        <div class="form-row">
            <label>Resources / paths / keywords (one per line):</label>
            <textarea name="resources[]" rows="4" placeholder="cloud&#10;/admin&#10;regex:^/custom.*$"></textarea>
            <small class="field-help">
                Enter cloud or /cloud for auto-regex. Use regex:^/custom.*$ for raw regex.
            </small>
        </div>
    `;
    return container;
}

function addRule() {
    const rulesContainer = document.getElementById('rulesContainer');
    rulesContainer.appendChild(createRuleCard());
}

function removeRule(button) {
    const card = button.closest('.rule-card');
    const rulesContainer = document.getElementById('rulesContainer');
    if (rulesContainer.children.length > 1) {
        rulesContainer.removeChild(card);
    } else {
        const inputs = card.querySelectorAll('input, textarea');
        inputs.forEach(i => i.value = '');
        const selects = card.querySelectorAll('select');
        selects.forEach(s => s.value = 'one_factor');
    }
}

function copyYaml() {
    const textarea = document.getElementById('yamlOutput');
    const text = textarea.value;
    if (!text) {
        alert('No YAML to copy. Generate YAML first.');
        return;
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
            alert('YAML copied to clipboard.');
        }, function () {
            alert('Unable to copy YAML. Please copy manually.');
        });
    } else {
        textarea.select();
        document.execCommand('copy');
        alert('YAML copied to clipboard.');
    }
}

function clearForm() {
    const form = document.getElementById('policyForm');
    form.reset();

    const rulesContainer = document.getElementById('rulesContainer');
    rulesContainer.innerHTML = '';
    rulesContainer.appendChild(createRuleCard());

    document.getElementById('yamlOutput').value = '';
}
</script>
</body>
</html>