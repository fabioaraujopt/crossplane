package validate

import "testing"

func TestIsHCLContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name: "Vault policy - simple path",
			content: `path "secret/data/dev/*" {
  capabilities = ["read"]
}`,
			expected: true,
		},
		{
			name: "Vault policy - multiple paths",
			content: `path "secret/data/%s/%s/*" {
  capabilities = ["read"]
}
path "secret/metadata/%s/%s/*" {
  capabilities = ["read"]
}`,
			expected: true,
		},
		{
			name:     "JSON - AWS IAM policy",
			content:  `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}`,
			expected: false,
		},
		{
			name: "JSON - multiline IAM policy",
			content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*"
    }
  ]
}`,
			expected: false,
		},
		{
			name:     "Empty string",
			content:  "",
			expected: false,
		},
		{
			name:     "Simple string",
			content:  "hello world",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHCLContent(tt.content)
			if got != tt.expected {
				t.Errorf("isHCLContent() = %v, want %v for content: %s", got, tt.expected, tt.content)
			}
		})
	}
}

func TestCountFormatPlaceholders(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		expected int
	}{
		// Simple %s placeholders
		{"single %s", "%s", 1},
		{"double %s", "%s-%s", 2},
		{"triple %s", "%s/%s/%s", 3},

		// Different verbs
		{"integer %d", "%d", 1},
		{"generic %v", "%v", 1},
		{"boolean %t", "%t", 1},
		{"hex %x", "%x", 1},
		{"hex upper %X", "%X", 1},
		{"octal %o", "%o", 1},
		{"float %f", "%.2f", 1},
		{"pointer %p", "%p", 1},
		{"type %T", "%T", 1},
		{"quoted %q", "%q", 1},
		{"unicode %U", "%U", 1},
		{"binary %b", "%b", 1},
		{"char %c", "%c", 1},
		{"octal with prefix %O", "%O", 1},
		{"scientific %e", "%e", 1},
		{"scientific upper %E", "%E", 1},
		{"compact %g", "%g", 1},
		{"compact upper %G", "%G", 1},
		{"float alt %F", "%F", 1},

		// Mixed verbs
		{"mixed s and d", "%s-%d", 2},
		{"mixed s d v", "%s/%d/%v", 3},

		// Positional placeholders
		{"positional [1]s", "%[1]s", 1},
		{"positional [2]s", "%[2]s", 2},
		{"positional [1]s [2]s", "%[1]s/%[2]s", 2},
		{"positional reuse", "%[1]s/*\n%[2]s/*", 2},
		{"positional with gap", "%[1]s %[3]s", 3}, // need at least 3 args
		{"high positional", "%[10]s", 10},

		// Positional with different verbs
		{"positional [1]d", "%[1]d", 1},
		{"positional [2]v", "%[2]v", 2},

		// Width and precision
		{"width", "%10s", 1},
		{"precision", "%.5s", 1},
		{"width and precision", "%10.5s", 1},
		{"width and precision float", "%10.2f", 1},

		// Flags
		{"flag minus", "%-10s", 1},
		{"flag plus", "%+d", 1},
		{"flag hash", "%#x", 1},
		{"flag space", "% d", 1},
		{"flag zero", "%05d", 1},
		{"multiple flags", "%-+10d", 1},

		// Complex combinations
		{"positional with width", "%[1]10s", 1},
		{"positional with precision", "%[2].5s", 2},
		{"positional with flags", "%[1]-10s", 1},
		{"complex format", "%[1]s-%[2]d-%[1]s", 2}, // reuses [1], max is [2]

		// Real-world Crossplane patterns
		{"arn pattern", "arn:aws:iam::%s:role/%s", 2},
		{"bucket policy", `"%[1]s/*","%[2]s/*"`, 2},
		{"eks oidc", "arn:aws:iam::%s:oidc-provider/%s", 2},
		{"json template", `{"clusterName":"%s","region":"%s"}`, 2},

		// Edge cases
		{"empty string", "", 0},
		{"no placeholders", "hello world", 0},
		{"escaped percent", "100%% complete", 0}, // %% is escape, not placeholder
		{"percent in text", "save 50%", 0},       // lone % without verb
		{"mixed escaped and real", "100%% of %s", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countFormatPlaceholders(tt.format)
			if got != tt.expected {
				t.Errorf("countFormatPlaceholders(%q) = %d, want %d", tt.format, got, tt.expected)
			}
		})
	}
}
