"""Check that the Sprint 2 stack starts with default limits and forwards through nginx."""

import json
import socket
import unittest
from urllib.request import urlopen

from scripts import transport_stack
from scripts.transport_stack import HOST, NGINX_CONF, transport_stack as start_stack


try:
    transport_stack.nginx_binary()
    NGINX_MISSING = None
except RuntimeError as error:
    NGINX_MISSING = str(error)


def get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read())


class NginxConfigTests(unittest.TestCase):
    def test_header_limits_are_left_at_defaults(self):
        config = NGINX_CONF.format(prefix="/tmp/x", host=HOST, port=1, app_port=2)
        self.assertNotIn("client_header_buffer_size", config)
        self.assertNotIn("large_client_header_buffers", config)

    def test_paths_are_quoted(self):
        config = NGINX_CONF.format(prefix="/tmp/with space", host=HOST, port=1, app_port=2)
        self.assertIn('pid "/tmp/with space/nginx.pid";', config)


@unittest.skipIf(NGINX_MISSING, NGINX_MISSING)
class TransportStackTests(unittest.TestCase):
    def test_request_reaches_app_through_nginx(self):
        with start_stack() as stack:
            self.assertEqual(get_json(f"{stack['url']}/health"),
                             {"status": "ok", "proxied_by": "nginx"})
            # Only nginx adds X-Proxied-By, so a direct request must not carry it.
            self.assertEqual(get_json(f"{stack['app_url']}/health"),
                             {"status": "ok", "proxied_by": None})
            self.assertIn("GET /health", stack["logs"]["nginx_access"].read_text())

    def test_servers_stop_when_the_block_exits(self):
        with start_stack() as stack:
            port = int(stack["url"].rsplit(":", 1)[1])
        with self.assertRaises(OSError):
            socket.create_connection((HOST, port), timeout=0.5).close()


if __name__ == "__main__":
    unittest.main()
