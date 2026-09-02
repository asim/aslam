package tools

import "testing"

func TestVerifyAuthResults(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		from    string
		want    bool
		comment string
	}{
		{
			name:   "dmarc pass",
			header: "mx.google.com; dkim=pass header.i=@aslam.me header.s=s1 header.b=abc; spf=pass (google.com: domain of asim@aslam.me designates 1.2.3.4 as permitted sender) smtp.mailfrom=asim@aslam.me; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=aslam.me",
			from:   "asim@aslam.me",
			want:   true,
		},
		{
			name:   "no dmarc policy but dkim passes and aligns",
			header: "mx.google.com; dkim=pass header.i=@aslam.me header.s=s1; spf=none; dmarc=none",
			from:   "Asim <asim@aslam.me>",
			want:   true,
		},
		{
			name:   "no dmarc policy but spf passes and aligns",
			header: "mx.google.com; dkim=none; spf=pass (google.com: domain of asim@aslam.me designates 1.2.3.4 as permitted sender) smtp.mailfrom=asim@aslam.me; dmarc=none",
			from:   "asim@aslam.me",
			want:   true,
		},
		{
			name:    "dkim passes for an unrelated domain",
			header:  "mx.google.com; dkim=pass header.i=@attacker.example header.s=s1; spf=none; dmarc=fail",
			from:    "asim@aslam.me",
			want:    false,
			comment: "a valid signature from another domain must not vouch for this From",
		},
		{
			name:    "spf passes but envelope domain differs",
			header:  "mx.google.com; dkim=none; spf=pass smtp.mailfrom=bounce@attacker.example; dmarc=fail",
			from:    "asim@aslam.me",
			want:    false,
			comment: "classic From-header spoof behind a passing SPF for another domain",
		},
		{
			name:    "everything fails",
			header:  "mx.google.com; dkim=fail; spf=fail; dmarc=fail (p=REJECT) header.from=aslam.me",
			from:    "asim@aslam.me",
			want:    false,
			comment: "the case Gmail would normally bin as spam",
		},
		{
			name:    "no header at all",
			header:  "",
			from:    "asim@aslam.me",
			want:    false,
			comment: "cannot verify, so must not be trusted",
		},
		{
			name:    "forged header from a server that is not ours",
			header:  "attacker.example; dmarc=pass (p=NONE) header.from=aslam.me; spf=pass smtp.mailfrom=asim@aslam.me",
			from:    "asim@aslam.me",
			want:    false,
			comment: "sender-supplied Authentication-Results must be ignored",
		},
		{
			name:   "relaxed alignment with a subdomain",
			header: "mx.google.com; dkim=pass header.d=aslam.me header.s=s1; dmarc=none",
			from:   "asim@mail.aslam.me",
			want:   true,
		},
		{
			name:    "parent domain does not inherit from a child signature",
			header:  "mx.google.com; dkim=pass header.d=mail.aslam.me; dmarc=none",
			from:    "asim@aslam.me",
			want:    false,
			comment: "alignment is only relaxed downward",
		},
		{
			name:   "comment containing a semicolon does not break parsing",
			header: "mx.google.com; spf=pass (google.com: sender ok; really) smtp.mailfrom=asim@aslam.me; dmarc=none",
			from:   "asim@aslam.me",
			want:   true,
		},
		{
			name:    "unparseable From",
			header:  "mx.google.com; dmarc=pass",
			from:    "not-an-address",
			want:    false,
			comment: "no domain to align against",
		},
		{
			name:   "case insensitive",
			header: "MX.GOOGLE.COM; DMARC=PASS (p=REJECT) header.from=ASLAM.ME",
			from:   "ASIM@ASLAM.ME",
			want:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := VerifyAuthResults(tc.header, tc.from)
			if got != tc.want {
				t.Errorf("VerifyAuthResults(%q, %q) = %v (%s), want %v. %s",
					tc.header, tc.from, got, reason, tc.want, tc.comment)
			}
		})
	}
}

func TestAligned(t *testing.T) {
	tests := []struct {
		auth, from string
		want       bool
	}{
		{"aslam.me", "aslam.me", true},
		{"aslam.me", "mail.aslam.me", true},
		{"mail.aslam.me", "aslam.me", false},
		{"slam.me", "aslam.me", false}, // suffix match must respect the dot
		{"", "aslam.me", false},
		{"aslam.me", "", false},
	}
	for _, tc := range tests {
		if got := aligned(tc.auth, tc.from); got != tc.want {
			t.Errorf("aligned(%q, %q) = %v, want %v", tc.auth, tc.from, got, tc.want)
		}
	}
}
