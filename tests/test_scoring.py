import unittest
import tempfile
import os
from unittest.mock import MagicMock, patch

from app.ml_model import classify_url, encode_url, read_labeled_csv, url_host_group
from app.xgb_model import FEATURE_NAMES, _domain_split, classify_url_xgboost, extract_url_features
from app.scanner import (
    PageParser,
    ScanError,
    ScanRateLimiter,
    check_ip_reputation,
    check_ssl,
    expand_link,
    lookup_dns,
    lookup_website_age,
    normalize_url,
    resolve_public,
    scan_url,
    _page_details,
    _registrable_domain,
    _url_checks,
)
from app.scoring import score_scan


class ScoringTests(unittest.TestCase):
    def test_score_is_capped_at_5(self):
        result = score_scan([{"triggered": True, "weight": 80}, {"triggered": True, "weight": 40}])
        self.assertEqual(result, {"risk_score": 5.0, "max_score": 5, "verdict": "High Risk"})

    def test_untriggered_checks_do_not_contribute(self):
        result = score_scan([{"triggered": False, "weight": 100}, {"triggered": True, "weight": 8}])
        self.assertEqual(result, {"risk_score": 0.4, "max_score": 5, "verdict": "Low Risk"})

    def test_verdict_thresholds(self):
        self.assertEqual(score_scan([{"triggered": True, "weight": 30}])["verdict"], "Medium Risk")
        self.assertEqual(score_scan([{"triggered": True, "weight": 31}])["verdict"], "Medium Risk")
        self.assertEqual(score_scan([{"triggered": True, "weight": 59}])["verdict"], "Medium Risk")
        self.assertEqual(score_scan([{"triggered": True, "weight": 70}])["verdict"], "High Risk")

    def test_normalizes_missing_scheme_and_hostname_case(self):
        self.assertEqual(normalize_url("Example.COM/path"), "https://example.com/path")

    def test_extracts_registered_domain_for_co_in_host(self):
        self.assertEqual(_registrable_domain("www.phishguard.co.in"), "phishguard.co.in")

    def test_dns_lookup_returns_public_address_records(self):
        with patch("app.scanner.resolve_public", return_value=["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]):
            result = lookup_dns("example.com")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual([record["type"] for record in result["records"]], ["A", "AAAA"])

    def test_website_age_reports_registration_data_when_available(self):
        with patch("app.scanner._rdap_details", return_value={"age_days": 120, "registered_on": "2026-06-18"}):
            result = lookup_website_age("www.example.com")
        self.assertEqual(result, {
            "status": "available", "domain": "example.com",
            "age_days": 120, "registered_on": "2026-06-18",
        })

    def test_link_expander_follows_redirects_without_downloading_page_body(self):
        chain = ["https://bit.ly/demo", "https://example.com/final"]
        with patch("app.scanner.safe_request", return_value=(200, {}, b"", chain)) as request:
            result = expand_link("https://bit.ly/demo")
        request.assert_called_once_with("https://bit.ly/demo", read_body=False)
        self.assertEqual(result["final_url"], chain[-1])

    def test_ssl_checker_reports_verified_certificate(self):
        tls_socket = MagicMock()
        tls_socket.getpeercert.return_value = {
            "issuer": ((("organizationName", "Example CA"),),),
            "notAfter": "Dec 31 23:59:59 2030 GMT",
        }
        with (
            patch("app.scanner.resolve_public", return_value=["93.184.216.34"]),
            patch("app.scanner._tls_socket", return_value=tls_socket),
        ):
            result = check_ssl("example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["expires_on"], "2030-12-31")
        tls_socket.close.assert_called_once()

    def test_ip_reputation_requires_public_ip_and_reports_missing_provider_key(self):
        with patch.dict(os.environ, {}, clear=True):
            result = check_ip_reputation("8.8.8.8")
        self.assertEqual(result["status"], "not_configured")
        with self.assertRaises(ScanError):
            check_ip_reputation("127.0.0.1")

    def test_rejects_non_http_scheme_and_allows_private_targets_for_static_analysis(self):
        for url in ("ftp://example.com", "http://localhost"):
            with self.subTest(url=url), self.assertRaises(ScanError):
                normalize_url(url)
        self.assertEqual(normalize_url("http://127.0.0.1"), "http://127.0.0.1/")
        self.assertEqual(normalize_url("http://192.168.1.1"), "http://192.168.1.1/")

    def test_detects_brand_impersonation_and_sensitive_words(self):
        normalized = normalize_url("paypal-account-update.example.com/signin")
        checks_list = _url_checks(normalized, "paypal-account-update.example.com", "example.com")
        checks = {check["name"]: check for check in checks_list}
        self.assertTrue(checks["brand_impersonation"]["triggered"])
        self.assertTrue(checks["sensitive_keywords"]["triggered"])
        self.assertGreater(score_scan(checks_list)["risk_score"], 2.5)

    def test_detects_indian_brand_impersonation_but_accepts_official_domain(self):
        suspicious = normalize_url("sbi-login.example.co.in")
        suspicious_checks = {
            check["name"]: check
            for check in _url_checks(suspicious, "sbi-login.example.co.in", "example.co.in")
        }
        official = normalize_url("https://www.sbi.co.in/")
        official_checks = {
            check["name"]: check
            for check in _url_checks(official, "www.sbi.co.in", "sbi.co.in")
        }
        self.assertTrue(suspicious_checks["brand_impersonation"]["triggered"])
        self.assertFalse(official_checks["brand_impersonation"]["triggered"])

    def test_blocks_private_addresses_returned_by_dns(self):
        private_result = [(None, None, None, None, ("10.0.0.7", 0))]
        with patch("app.scanner.socket.getaddrinfo", return_value=private_result):
            self.assertEqual(resolve_public("attacker.example", 443), [])

    def test_private_ip_urls_do_not_crash_static_analysis(self):
        url = normalize_url("http://127.0.0.1/login")
        result = scan_url(url)
        self.assertEqual(result["details"]["domain"]["dns"]["status"], "warning")
        self.assertLessEqual(result["risk_score"], 5)

    def test_detects_hidden_iframe_attributes_and_styles(self):
        parser = PageParser()
        parser.feed('<iframe hidden></iframe><iframe style="display:none"></iframe><iframe></iframe>')
        self.assertEqual(parser.hidden_iframes, 2)

    def test_page_checks_find_login_and_mismatched_brand(self):
        page = b'<title>PayPal Sign In</title><form><input type="password"></form><iframe hidden></iframe>'
        response = (200, {"content-type": "text/html; charset=utf-8"}, page, ["https://example.com/"])
        with patch("app.scanner.safe_request", return_value=response):
            details, checks = _page_details("https://example.com/", "example.com")
        names = {item["name"] for item in checks if item["triggered"]}
        self.assertTrue(details["login_form"])
        self.assertIn("password_form", names)
        self.assertIn("hidden_iframe", names)
        self.assertIn("page_brand_mismatch", names)

    def test_detects_password_form_submitting_to_another_domain(self):
        page = b'<form action="https://attacker.example/collect"><input type="password"></form>'
        cases = (
            ("https://example.com/", "example.com", "https://attacker.example/collect", True),
            ("https://login.example.co.uk/", "login.example.co.uk", "https://example.co.uk/collect", False),
            ("https://example.co.uk/", "example.co.uk", "https://attacker.co.uk/collect", True),
        )
        for page_url, host, action, should_trigger in cases:
            with self.subTest(page_url=page_url, action=action):
                content = page.replace(b"https://attacker.example/collect", action.encode())
                if action == "https://example.co.uk/collect":
                    content = b'<form action="https://example.co.uk/collect"><input type="password"></form>'
                response = (200, {"content-type": "text/html; charset=utf-8"}, content, [page_url])
                with patch("app.scanner.safe_request", return_value=response):
                    _, checks = _page_details(page_url, host)
                triggered = {item["name"] for item in checks if item["triggered"]}
                self.assertEqual("credential_exfiltration" in triggered, should_trigger)
                if should_trigger:
                    self.assertGreater(score_scan(checks)["risk_score"], 4.5)

    def test_scan_response_contains_result_and_domain_page_feed_details(self):
        domain = {
            "domain": "example.com", "dns": {"status": "resolved", "ip": "93.184.216.34"},
            "age_days": 9000, "registered_on": "2000-01-01",
            "ssl": {"valid": True, "issuer": "Example CA", "expires_on": "2030-01-01"},
        }
        page = {
            "status_code": 200, "redirect_chain": ["https://example.com/"],
            "title": "Example", "login_form": False, "forms_cross_domain": False,
            "hidden_iframes": 0, "external_links": 0, "favicon": None,
        }
        with (
            patch("app.scanner.resolve_public", return_value=["93.184.216.34"]),
            patch("app.scanner._domain_details", return_value=domain),
            patch("app.scanner._page_details", return_value=(page, [])),
            patch("app.scanner._feed_results", return_value={"feeds": {}, "checks": []}),
            patch("app.scanner.classify_url", return_value={
                "status": "ready", "prediction": "phishing",
                "phishing_probability": 0.91, "confidence": 0.91, "threshold": 0.8,
            }),
            patch("app.scanner.classify_url_xgboost", return_value={
                "status": "ready", "prediction": "phishing",
                "phishing_probability": 0.93, "confidence": 0.93, "threshold": 0.8,
            }),
        ):
            result = scan_url("https://example.com")
        self.assertEqual(result["verdict"], "Medium Risk")
        self.assertGreaterEqual(result["risk_score"], 1.5)
        self.assertEqual(result["max_score"], 5)
        self.assertEqual(result["details"]["domain"], domain)
        self.assertEqual(result["details"]["page"], page)
        self.assertEqual(result["details"]["model"]["phishing_probability"], 0.91)
        self.assertEqual(result["details"]["xgboost_model"]["phishing_probability"], 0.93)
        self.assertIn("trained_url_models", {check["name"] for check in result["checks"]})
        self.assertIn("all_checks", result)

    def test_rate_limiter_enforces_window_and_resets_after_expiry(self):
        limiter = ScanRateLimiter(limit=1, window_seconds=60)
        with patch("app.scanner.time.monotonic", side_effect=[1, 2, 62]):
            self.assertTrue(limiter.allow("client"))
            self.assertFalse(limiter.allow("client"))
            self.assertTrue(limiter.allow("client"))

    def test_model_reports_missing_artifact_without_claiming_prediction(self):
        with tempfile.TemporaryDirectory() as directory:
            result = classify_url("https://example.com", model_path=f"{directory}/missing.pt")
        self.assertEqual(result["status"], "not_trained")
        self.assertIsNone(result["phishing_probability"])

    def test_xgboost_extractor_matches_notebook_url_features(self):
        features = extract_url_features("https://login-example.com/account/reset?a=1&b=2")
        self.assertEqual(len(features), len(FEATURE_NAMES))
        self.assertEqual(features[:8], [0.0, 0.0, 0.0, 2.0, 0.0, 0.0, 0.0, 1.0])
        self.assertEqual(features[10], 2.0)
        self.assertEqual(features[11], 2.0)
        self.assertEqual(extract_url_features("https://example.com/" + "a" * 50)[2], 1.0)

    def test_xgboost_marks_redirect_and_shortener_features(self):
        features = extract_url_features("http://bit.ly/a//b")
        self.assertEqual(features[4], 1.0)
        self.assertEqual(features[6], 1.0)

    def test_xgboost_classifier_reports_missing_artifact_without_prediction(self):
        with tempfile.TemporaryDirectory() as directory:
            result = classify_url_xgboost("https://example.com", model_path=f"{directory}/missing.json")
        self.assertEqual(result["status"], "not_trained")
        self.assertIsNone(result["phishing_probability"])

    def test_xgboost_validation_split_keeps_each_host_in_one_partition(self):
        rows = [
            ("https://safe-one.example/a", 0), ("https://www.safe-one.example/b", 0),
            ("https://safe-two.example", 0), ("https://phish-one.example", 1),
            ("https://phish-two.example/a", 1), ("https://phish-two.example/b", 1),
        ]
        train, validation = _domain_split(rows, 0.34, 42)
        train_hosts = {url_host_group(url) for url, _ in train}
        validation_hosts = {url_host_group(url) for url, _ in validation}
        self.assertFalse(train_hosts & validation_hosts)
        self.assertEqual({label for _, label in train}, {0, 1})
        self.assertEqual({label for _, label in validation}, {0, 1})

    def test_url_encoder_preserves_byte_values_and_limit(self):
        self.assertEqual(encode_url("ab", max_bytes=3), [98, 99])
        self.assertEqual(len(encode_url("a" * 20, max_bytes=4)), 4)

    def test_training_csv_accepts_both_classes(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".csv", delete=False) as dataset:
            dataset.write("url,label\nhttps://example.com,safe\nhttp://bad.example,phishing\n")
            path = dataset.name
        try:
            self.assertEqual(read_labeled_csv(path), [
                ("https://example.com", 0),
                ("http://bad.example", 1),
            ])
        finally:
            import os
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
