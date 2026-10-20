import tempfile
import unittest
from pathlib import Path

from sec360_collector.queue import DeliveryQueue


class DeliveryQueueTests(unittest.TestCase):
    def test_sequences_and_idempotent_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = DeliveryQueue(str(Path(directory) / "queue.db"))
            self.assertEqual(queue.next_sequence("wlc"), 1)
            self.assertEqual(queue.next_sequence("wlc"), 2)
            self.assertEqual(queue.next_sequence("switch"), 1)
            payload = {"snapshot_id": "snap-1", "source_id": "wlc"}
            queue.enqueue(payload)
            queue.enqueue(payload)
            self.assertEqual(queue.depth(), 1)
            delivery = queue.pending()[0]
            self.assertEqual(delivery["payload"], payload)
            queue.delivered(delivery["id"])
            self.assertEqual(queue.depth(), 0)


if __name__ == "__main__":
    unittest.main()
