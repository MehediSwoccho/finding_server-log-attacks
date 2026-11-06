import unittest

from app.analyzer import chunk_entries


class ChunkEntriesTests(unittest.TestCase):
    def test_packs_whole_entries_and_preserves_line_numbers(self):
        entries = [(1, '{"line":1}'), (2, '{"line":2}'), (3, '{"line":3}')]
        chunks = list(chunk_entries(entries, lambda value: len(value), max_tokens=22))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0][0], '{"line":1}\n{"line":2}')
        self.assertEqual(chunks[1][0], '{"line":3}')
        self.assertTrue(all(tokens <= 22 for _, tokens in chunks))

    def test_never_splits_an_oversized_entry(self):
        with self.assertRaisesRegex(ValueError, "line 7"):
            list(chunk_entries([(7, "x" * 11)], len, max_tokens=10))

    def test_empty_input_has_no_chunks(self):
        self.assertEqual(list(chunk_entries([], len, max_tokens=10)), [])


if __name__ == "__main__":
    unittest.main()
