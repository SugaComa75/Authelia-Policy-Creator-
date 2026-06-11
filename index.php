<?php
// Authelia Policy Builder - simple standalone PHP tool
// This tool generates YAML only. It does not validate Authelia configuration.

// Allowed policies for basic sanitisation.
$allowed_policies = ['deny', 'bypass', 'one_factor', 'two_factor'];

// Helper: escape double quotes for YAML safety.
function escape_quotes($str) {
    return str_replace('"', '\\"', trim($str));
}

// Helper: clean a friendly path for Authelia resource output.
//
// Important: Authelia resource examples generally use paths like /cloud/admin.php,
// not PHP preg_quote output like \/cloud\/admin\.php. For friendly path mode
// we therefore keep normal URL path characters as typed and only strip characters
// that are unsafe in a simple path. Advanced users can still use regex: to supply
// exact custom regex.
function clean_friendly_path($path) {
    $path = trim($path);

    // Remove anchors accidentally pasted into friendly mode.
    $path = preg_replace('/^\^+/', '', $path);
    $path = preg_replace('/\$+$/', '', $path);

    // Keep common URL path characters. Remove quotes and whitespace.
    $path = preg_replace('/["\'`\s]/', '', $path);

    // Collapse repeated slashes.
    $path = preg_replace('#/+#', '/', $path);

    return trim($path, '/');
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

    $safe_path = clean_friendly_path($value);

    if ($safe_path === '') {
        return '^/([/?].*)?$';
    }

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
    $has_resources = !empty($rule['has_resources']) || trim($rule['resources'] ?? '') !== '';
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

// Helper: sort policies where equally-specific rules may overlap.
// Deny must come before allow rules for the same resource, otherwise Authelia stops at the allow rule.
function policy_priority($rule) {
    $policy = $rule['policy'] ?? 'deny';

    if ($policy === 'deny') {
        return 0;
    }

    if ($policy === 'two_factor') {
        return 1;
    }

    if ($policy === 'one_factor') {
        return 2;
    }

    if ($policy === 'bypass') {
        return 3;
    }

    return 4;
}

// Helper: put longer resource regexes first when rules share the same domain.
// Example: /cloud/admin.php must be checked before /cloud.
function resource_specificity($rule) {
    $resources = trim($rule['resources'] ?? '');
    return strlen($resources);
}

// Extract a scalar YAML value from a line such as domain: "example.com".
function extract_yaml_scalar($line, $key) {
    if (!preg_match('/^\s*' . preg_quote($key, '/') . '\s*:\s*(.*?)\s*$/', $line, $m)) {
        return '';
    }

    $value = trim($m[1]);
    $value = trim($value, "'\"");
    return $value;
}

// Extract an existing access_control section from pasted YAML and return raw rule blocks.
// This is intentionally lightweight and dependency-free. It preserves each existing rule block as text.
function parse_existing_access_control($yaml_text) {
    $result = [
        'default_policy' => '',
        'rules' => [],
    ];

    $yaml_text = trim((string)$yaml_text);
    if ($yaml_text === '') {
        return $result;
    }

    $lines = preg_split('/\r\n|\r|\n/', $yaml_text);
    $in_access = false;
    $in_rules = false;
    $current = [];
    $order = 0;

    foreach ($lines as $line) {
        if (preg_match('/^access_control:\s*$/', $line)) {
            $in_access = true;
            $in_rules = false;
            continue;
        }

        // If the user pasted only the contents below access_control, still accept it.
        if (!$in_access && preg_match('/^\s*(default_policy|rules):/', $line)) {
            $in_access = true;
        }

        if (!$in_access) {
            continue;
        }

        if (preg_match('/^\S[^:]*:\s*$/', $line) && !preg_match('/^access_control:\s*$/', $line)) {
            // A new top-level YAML section means access_control has ended.
            if (!empty($current)) {
                $result['rules'][] = build_existing_rule_from_lines($current, $order++);
                $current = [];
            }
            break;
        }

        if (preg_match('/^\s*default_policy\s*:\s*(.*?)\s*$/', $line, $m)) {
            $result['default_policy'] = trim(trim($m[1]), "'\"");
            continue;
        }

        if (preg_match('/^\s*rules\s*:\s*$/', $line)) {
            $in_rules = true;
            continue;
        }

        if ($in_rules) {
            if (preg_match('/^\s*-\s+domain\s*:/', $line)) {
                if (!empty($current)) {
                    $result['rules'][] = build_existing_rule_from_lines($current, $order++);
                    $current = [];
                }
                $current[] = $line;
            } elseif (!empty($current)) {
                $current[] = $line;
            }
        }
    }

    if (!empty($current)) {
        $result['rules'][] = build_existing_rule_from_lines($current, $order++);
    }

    return $result;
}

// Convert a raw existing YAML rule block into sortable metadata while keeping the original YAML text.
function build_existing_rule_from_lines($lines, $order) {
    $domain = '';
    $policy = '';
    $has_resources = false;

    foreach ($lines as $line) {
        if (preg_match('/^\s*-\s+domain\s*:\s*(.*?)\s*$/', $line, $m)) {
            $domain = trim(trim($m[1]), "'\"");
        }
        if (preg_match('/^\s*policy\s*:\s*(.*?)\s*$/', $line, $m)) {
            $policy = trim(trim($m[1]), "'\"");
        }
        if (preg_match('/^\s*resources\s*:\s*$/', $line)) {
            $has_resources = true;
        }
    }

    return [
        'type' => 'existing',
        'domain' => $domain,
        'policy' => $policy ?: 'deny',
        'has_resources' => $has_resources,
        'raw' => normalise_existing_rule_indent($lines),
        'original' => $order,
    ];
}

// Normalise existing rule indentation to fit under access_control -> rules.
function normalise_existing_rule_indent($lines) {
    $trimmed = [];
    foreach ($lines as $line) {
        $trimmed[] = rtrim($line);
    }

    // Find indentation of first "- domain" line and shift it to 4 spaces.
    $first_indent = 0;
    foreach ($trimmed as $line) {
        if (preg_match('/^(\s*)-\s+domain\s*:/', $line, $m)) {
            $first_indent = strlen($m[1]);
            break;
        }
    }

    $out = [];
    foreach ($trimmed as $line) {
        if ($line === '') {
            continue;
        }
        $remove = min($first_indent, strspn($line, ' '));
        $out[] = '    ' . substr($line, $remove);
    }

    return implode("\n", $out) . "\n";
}

// Build a new rule into a raw YAML block and sortable metadata.
function build_new_rule($rule) {
    $raw = '    - domain: "' . escape_quotes($rule['domain']) . '"' . "\n";

    $resources_block = build_resources_block($rule['resources']);
    if ($resources_block !== '') {
        $raw .= $resources_block;
    }

    $raw .= "      policy: " . $rule['policy'] . "\n";

    $subject_block = build_subject_block($rule['users'], $rule['groups']);
    if ($subject_block !== '') {
        $raw .= $subject_block;
    }

    return [
        'type' => 'new',
        'domain' => $rule['domain'],
        'policy' => $rule['policy'],
        'resources' => $rule['resources'],
        'has_resources' => trim($rule['resources']) !== '',
        'raw' => $raw,
        'original' => $rule['original'],
    ];
}

// Generate YAML if form submitted.
$yaml_output = '';
$merge_notice = '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $existing_yaml = $_POST['existing_yaml'] ?? '';
    $existing = parse_existing_access_control($existing_yaml);

    $default_policy = isset($_POST['default_policy']) ? trim($_POST['default_policy']) : 'deny';
    if (!in_array($default_policy, $allowed_policies, true)) {
        $default_policy = 'deny';
    }

    // If the user pasted an existing config and did not change the default selector, honour the pasted value.
    if (!empty($existing['default_policy']) && (empty($_POST['default_policy_changed']) || $_POST['default_policy_changed'] !== '1')) {
        if (in_array($existing['default_policy'], $allowed_policies, true)) {
            $default_policy = $existing['default_policy'];
        }
    }

    $rules = [];

    foreach ($existing['rules'] as $existing_rule) {
        $existing_rule['original'] = 100000 + ($existing_rule['original'] ?? 0);
        $rules[] = $existing_rule;
    }

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

            $rules[] = build_new_rule([
                'domain'    => $domain,
                'policy'    => $policy,
                'users'     => $users_arr[$i] ?? '',
                'groups'    => $groups_arr[$i] ?? '',
                'resources' => $resources_arr[$i] ?? '',
                'original'  => $i,
            ]);
        }
    }

    usort($rules, function ($a, $b) {
        $priority = rule_priority($a) <=> rule_priority($b);
        if ($priority !== 0) {
            return $priority;
        }

        $domainCompare = strcmp($a['domain'] ?? '', $b['domain'] ?? '');
        if ($domainCompare !== 0) {
            return $domainCompare;
        }

        $aHasResources = !empty($a['has_resources']) || trim($a['resources'] ?? '') !== '';
        $bHasResources = !empty($b['has_resources']) || trim($b['resources'] ?? '') !== '';

        if ($aHasResources && $bHasResources) {
            // More specific/longer resource rules before broader ones.
            $specificity = resource_specificity($b) <=> resource_specificity($a);
            if ($specificity !== 0) {
                return $specificity;
            }

            $resourceCompare = strcmp($a['resources'] ?? '', $b['resources'] ?? '');
            if ($resourceCompare !== 0) {
                return $resourceCompare;
            }
        }

        $policyCompare = policy_priority($a) <=> policy_priority($b);
        if ($policyCompare !== 0) {
            return $policyCompare;
        }

        // Keep original order only after safety sorting has been applied.
        return ($a['original'] ?? 0) <=> ($b['original'] ?? 0);
    });

    $yaml = "access_control:\n";
    $yaml .= "  default_policy: " . $default_policy . "\n\n";
    $yaml .= "  rules:\n";

    foreach ($rules as $rule) {
        $yaml .= rtrim($rule['raw']) . "\n\n";
    }

    $yaml_output = trim($yaml) . "\n";

    if (trim($existing_yaml) !== '') {
        $merge_notice = 'Existing YAML was included and the combined rules were sorted into the recommended order.';
    }
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
                    <select name="default_policy" id="default_policy" onchange="markDefaultPolicyChanged()">
                        <?php $current_default = $_POST['default_policy'] ?? 'deny'; ?>
                        <option value="deny" <?php echo selected_policy($current_default, 'deny'); ?>>deny</option>
                        <option value="bypass" <?php echo selected_policy($current_default, 'bypass'); ?>>bypass</option>
                        <option value="one_factor" <?php echo selected_policy($current_default, 'one_factor'); ?>>one_factor</option>
                        <option value="two_factor" <?php echo selected_policy($current_default, 'two_factor'); ?>>two_factor</option>
                    </select>
                    <input type="hidden" name="default_policy_changed" id="default_policy_changed" value="<?php echo htmlspecialchars($_POST['default_policy_changed'] ?? '0', ENT_QUOTES); ?>">
                </div>

                <h2>Existing YAML Optional</h2>
                <p class="hint">
                    Paste your current <code>access_control</code> YAML here to merge it with new rules. Existing rules are preserved, then the combined output is sorted safely.
                </p>
                <div class="form-row">
                    <label for="existing_yaml">Current access_control YAML:</label>
                    <textarea name="existing_yaml" id="existing_yaml" rows="10" placeholder="access_control:
  default_policy: deny

  rules:
    - domain: &quot;tech.example.com&quot;
      policy: bypass"><?php echo htmlspecialchars($_POST['existing_yaml'] ?? '', ENT_QUOTES); ?></textarea>
                    <small class="field-help">
                        You can paste the full <code>access_control:</code> block, or just the <code>default_policy</code> and <code>rules</code> content. The tool does a simple merge and does not fully validate YAML.
                    </small>
                </div>

                <?php if ($merge_notice !== ''): ?>
                    <p class="success"><?php echo htmlspecialchars($merge_notice, ENT_QUOTES); ?></p>
                <?php endif; ?>

                <h2>New Rules to Add</h2>
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
                    $rule_count = (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && isset($_POST['domain']) && is_array($_POST['domain']))
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
                Copy this into your Authelia configuration. If you pasted existing YAML, this output is the merged replacement <code>access_control</code> block.
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
                <li><strong>existing YAML</strong> – paste your current rules to merge new rules into the right order.</li>
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
cloud            becomes "^/cloud([/?].*)?$"
/admin           becomes "^/admin([/?].*)?$"
/cloud/admin.php becomes "^/cloud/admin.php([/?].*)?$"
regex:^/x.*$     keeps "^/x.*$"
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

function markDefaultPolicyChanged() {
    const flag = document.getElementById('default_policy_changed');
    if (flag) {
        flag.value = '1';
    }
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

    const existingYaml = document.getElementById('existing_yaml');
    if (existingYaml) {
        existingYaml.value = '';
    }

    const policyChanged = document.getElementById('default_policy_changed');
    if (policyChanged) {
        policyChanged.value = '0';
    }

    document.getElementById('yamlOutput').value = '';
}
</script>
</body>
</html>
