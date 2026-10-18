"""Quick smoke tests for safe URL validation and packet parsing helpers."""
import unittest
from unittest.mock import patch
import dashboard

class WebsiteCheckerTests(unittest.TestCase):
    def test_invalid_scheme_rejected(self):
        r=dashboard.check_website('ftp://example.com')
        self.assertEqual(r['title'],'Invalid website URL')
    def test_empty_input_rejected(self):
        r=dashboard.check_website('  ')
        self.assertEqual(r['css'],'bad')
    def test_localhost_blocked(self):
        r=dashboard.check_website('http://localhost')
        self.assertIn('not allowed',r['error'])
    @patch('dashboard.socket.getaddrinfo',side_effect=__import__('socket').gaierror('not found'))
    def test_dns_failure_reported(self,mock_dns):
        r=dashboard.check_website('https://nonexistent.invalid')
        self.assertEqual(r['dns_status'],'Failed')
    @patch('dashboard.socket.getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',443))])
    @patch('dashboard.requests.get')
    def test_reachable_site_result(self,mock_get,mock_dns):
        mock_get.return_value.status_code=200
        mock_get.return_value.headers={}
        mock_get.return_value.close.return_value=None
        r=dashboard.check_website('https://example.com')
        self.assertEqual(r['title'],'Website is reachable')
        self.assertEqual(r['http_status'],200)

if __name__=='__main__': unittest.main(verbosity=2)
