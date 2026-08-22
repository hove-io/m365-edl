import ipaddress
import unittest

from scripts.generate_edl import GenerationError, extract_teams_media_networks


EXPECTED = [
    ipaddress.IPv4Network("52.112.0.0/14"),
    ipaddress.IPv4Network("52.120.0.0/14"),
]


class TeamsMediaParserTests(unittest.TestCase):
    def test_extracts_legacy_commercial_section_only(self) -> None:
        learn_html = """
        <h3>Media traffic: port ranges</h3>
        <h4>Microsoft 365, Office 365, and Office 365 GCC environments</h4>
        <p>52.112.0.0/14 52.120.0.0/14</p>
        <h4>Office 365 GCC High environment</h4>
        <p>52.127.88.0/21</p>
        <h4>Office 365 DoD environment</h4>
        <p>52.127.64.0/21</p>
        """

        self.assertEqual(extract_teams_media_networks(learn_html), EXPECTED)

    def test_extracts_current_commercial_section_only(self) -> None:
        learn_html = """
        <h2><span>Media processor IP ranges</span></h2>
        <h3>Microsoft 365 / Office 365</h3>
        <ul><li>52.112.0.0/14</li><li>52.120.0.0/14</li></ul>
        <h3>GCC High</h3>
        <ul><li>52.127.88.0/21</li></ul>
        <h3>DoD</h3>
        <ul><li>52.127.64.0/21</li></ul>
        """

        self.assertEqual(extract_teams_media_networks(learn_html), EXPECTED)

    def test_rejects_unexpected_commercial_range(self) -> None:
        learn_html = """
        <h2>Media processor IP ranges</h2>
        <h3>Microsoft 365 / Office 365</h3>
        <p>52.112.0.0/14 52.120.0.0/14 52.127.88.0/21</p>
        """

        with self.assertRaisesRegex(GenerationError, "Unexpected Teams media ranges"):
            extract_teams_media_networks(learn_html)


if __name__ == "__main__":
    unittest.main()
