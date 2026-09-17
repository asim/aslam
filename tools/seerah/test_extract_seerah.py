import unittest
import tempfile
import pathlib
import zipfile
import json

from extract_seerah import correct_source_text, write_archive
from seerah_question_marks import decision


class SourceCorrectionsTest(unittest.TestCase):
    def test_archive_format_and_reproducibility(self):
        data = {"title": "The Sealed Nectar", "pages": [{"number": 8, "text": "Allah — الله"}]}
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "seerah.zip"
            write_archive(output, data)
            first = output.read_bytes()
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.namelist(), ["seerah.json"])
                self.assertEqual(json.loads(archive.read("seerah.json")), data)
            write_archive(output, data)
            self.assertEqual(output.read_bytes(), first)

    def test_spacing_and_split_words(self):
        cases = {
            "‘Imran bin ‘Amr Muzaiqb?#146;": "‘Imran bin ‘Amr Muzaiqbâ’",
            "It was a privilege granted to Moses ? ?": "It was a privilege granted to Moses عليه السلام",
            "??? and clearly attested in the Qur’? ,": "and clearly attested in the Qur’an,",
            "All? saved her": "Allah saved her",
            "All? ’s favour": "Allah’s favour",
            "All? , the Sublime": "Allah, the Sublime",
            "All? u Akbar": "Allahu Akbar",
            "Qur’? ic verses": "Qur’anic verses",
            "Noble Qur’? .": "Noble Qur’an.",
            "reward the Muhsin? (good-doers,": "reward the Muhsinûn (good-doers,",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(correct_source_text(source), expected)

    def test_real_questions_and_unreviewed_text_are_preserved(self):
        for text in ["Qur'an", "Qur’ân?", "Allâh?", "Have you said all?",
                     "Moses ? ?", "???", "Muhsin? elsewhere",
                     "All?word", "SmallAll?", "[Al-Qur'an 37:103-107]"]:
            with self.subTest(text=text):
                self.assertEqual(correct_source_text(text), text)

    def test_verified_fragments_and_attached_markup(self):
        self.assertEqual(correct_source_text("east of Taim?#146; and west of Kufa"),
                         "east of Taimâ’ and west of Kufa")
        self.assertEqual(correct_source_text("Tham? , Tasam"), "Thamûd, Tasam")
        self.assertEqual(correct_source_text("Chapter T?H?/i>"), "Chapter Tâ-Hâ")
        self.assertEqual(correct_source_text("L?il? a illa Ana (Iq? at-as-Sal? )"),
                         "Lâ ilâha illa Ana (Iqâmat-as-Salât)")
        self.assertEqual(correct_source_text("Say: O Al-K? ir? (disbelievers)"),
                         "Say: O Al-Kâfirûn (disbelievers)")

    def test_damaged_name_next_to_real_question(self):
        source = 'My Lord is All? ?" [Bukhari 1/544]'
        self.assertEqual(correct_source_text(source), 'My Lord is Allah?" [Bukhari 1/544]')
        positions = [i for i, c in enumerate(source) if c == '?']
        self.assertEqual([decision(source, i)[0] for i in positions], ['Fixed', 'Keep'])


if __name__ == '__main__':
    unittest.main()
