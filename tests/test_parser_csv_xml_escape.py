import unittest

from forcastl.core.parser import EVTXParser


class ParserCsvXmlEscapeTests(unittest.TestCase):
    def test_csv_row_to_xml_escapes_attributes_and_text(self):
        parser = EVTXParser()
        row = {
            "Provider": 'Prov "A"&B',
            "EventId": "4688",
            "TimeCreated": '2026-02-12T10:00:00Z" bad',
            "Computer": "host<01>",
            "Channel": "Sec&Ops",
        }
        event_data = {
            "EventData": {
                "Data": [
                    {"@Name": 'Command"Name', "#text": 'cmd /c echo "<x>&y"'},
                ]
            }
        }

        xml = parser._csv_row_to_xml(row, event_data)

        self.assertIn('Provider Name="Prov &quot;A&quot;&amp;B"', xml)
        self.assertIn('SystemTime="2026-02-12T10:00:00Z&quot; bad"', xml)
        self.assertIn("<Computer>host&lt;01&gt;</Computer>", xml)
        self.assertIn("<Channel>Sec&amp;Ops</Channel>", xml)
        self.assertIn('Data Name="Command&quot;Name"', xml)
        self.assertIn("cmd /c echo \"&lt;x&gt;&amp;y\"", xml)


if __name__ == "__main__":
    unittest.main()
