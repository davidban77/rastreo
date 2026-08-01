use std::collections::VecDeque;

/// Records a sink has written but whose destination has not accepted yet, plus the byte count the
/// flush threshold is compared against. Every mutation updates both halves in the same statement
/// and no other mutation path exists, so the count and the contents cannot disagree. Entries leave
/// through `settle_front` (the head) or `settle_all` (the whole batch), each carrying the
/// destination's own outcome and removing nothing on an error. Removal without acceptance is made
/// conspicuous, not impossible: absent `pop`, `clear`, `drain`, or a `&mut` view of the entries, it
/// has to be written either as a settle against a fabricated `Ok` — which `settle_all` honours for
/// the whole batch, not just the head — or as a `mem::replace` of the whole buffer. Both are
/// review-visible by construction; neither is type-forbidden.
pub(crate) struct PendingBuffer<T> {
    entries: VecDeque<T>,
    bytes: usize,
}

// Each broker settles a different half of this surface, so only a build carrying both can judge a method dead.
#[cfg_attr(not(all(feature = "kafka", feature = "nats")), allow(dead_code))]
impl<T: AsRef<[u8]>> PendingBuffer<T> {
    pub(crate) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn front(&self) -> Option<&T> {
        self.entries.front()
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &T> {
        self.entries.iter()
    }

    pub(crate) fn reached_threshold(&self, threshold: usize) -> bool {
        self.bytes >= threshold
    }

    pub(crate) fn push(&mut self, entry: T) {
        self.bytes += entry.as_ref().len();
        self.entries.push_back(entry);
    }

    pub(crate) fn push_record(&mut self, data: &[u8])
    where
        T: From<Vec<u8>>,
    {
        self.push(T::from(data.to_vec()));
    }

    /// Drops the head when `outcome` is the destination's acceptance; an error keeps it, and
    /// everything written behind it, for the next attempt.
    pub(crate) fn settle_front<V, E>(&mut self, outcome: Result<V, E>) -> Result<V, E> {
        if outcome.is_ok() {
            if let Some(entry) = self.entries.pop_front() {
                let len = entry.as_ref().len();
                debug_assert!(self.bytes >= len, "byte count desynced from the entries");
                self.bytes -= len;
            }
        }
        outcome
    }

    /// Drops every entry when `outcome` is the destination's acceptance of the whole batch.
    pub(crate) fn settle_all<V, E>(&mut self, outcome: Result<V, E>) -> Result<V, E> {
        if outcome.is_ok() {
            self.entries.clear();
            self.bytes = 0;
        }
        outcome
    }

    /// Puts entries a destination refused back at the head, ahead of anything written since.
    pub(crate) fn restore_front(&mut self, mut batch: Self) {
        if batch.is_empty() {
            // Nothing to splice: the append-and-swap below would rebuild this buffer's allocation for no gain.
            return;
        }
        self.bytes += batch.bytes;
        batch.entries.append(&mut self.entries);
        self.entries = batch.entries;
    }
}

pub(crate) fn clamp_threshold(bytes: usize) -> usize {
    bytes.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffered(records: &[&[u8]]) -> PendingBuffer<Vec<u8>> {
        let mut buffer = PendingBuffer::new();
        for record in records {
            buffer.push_record(record);
        }
        buffer
    }

    fn entries(buffer: &PendingBuffer<Vec<u8>>) -> Vec<&[u8]> {
        buffer.iter().map(Vec::as_slice).collect()
    }

    fn summed_entry_bytes<T: AsRef<[u8]>>(buffer: &PendingBuffer<T>) -> usize {
        buffer.iter().map(|entry| entry.as_ref().len()).sum()
    }

    #[test]
    fn a_new_buffer_holds_nothing_and_owes_nothing() {
        let buffer: PendingBuffer<Vec<u8>> = PendingBuffer::new();
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.bytes(), 0);
        assert!(buffer.front().is_none());
    }

    #[test]
    fn push_record_keeps_each_record_a_distinct_entry() {
        let buffer = buffered(&[b"one\n", b"two\n", b"three\n"]);
        assert_eq!(
            buffer.len(),
            3,
            "a batched flush of 3 records must reach the destination as 3 entries, not one concatenated payload"
        );
        assert_eq!(
            entries(&buffer),
            [b"one\n".as_slice(), b"two\n", b"three\n"]
        );
        assert_eq!(buffer.bytes(), 4 + 4 + 6);
    }

    #[test]
    fn settle_front_on_acceptance_removes_the_head_and_debits_only_its_bytes() {
        let mut buffer = buffered(&[b"one\n", b"two\n", b"three\n"]);
        let settled = buffer.settle_front(Ok::<(), ()>(()));
        assert!(settled.is_ok());
        assert_eq!(entries(&buffer), [b"two\n".as_slice(), b"three\n"]);
        assert_eq!(buffer.bytes(), 4 + 6);
    }

    #[test]
    fn settle_front_on_refusal_keeps_the_head_and_everything_behind_it() {
        let mut buffer = buffered(&[b"one\n", b"two\n", b"three\n"]);
        let settled = buffer.settle_front(Err::<(), &str>("refused"));
        assert_eq!(settled, Err("refused"));
        assert_eq!(
            entries(&buffer),
            [b"one\n".as_slice(), b"two\n", b"three\n"]
        );
        assert_eq!(buffer.bytes(), 4 + 4 + 6);
    }

    #[test]
    fn settling_every_accepted_entry_leaves_an_empty_buffer_and_no_bytes() {
        let mut buffer = buffered(&[b"one\n", b"two\n", b"three\n"]);
        for _ in 0..3 {
            let _ = buffer.settle_front(Ok::<(), ()>(()));
        }
        assert!(buffer.is_empty());
        assert_eq!(buffer.bytes(), 0);
    }

    #[test]
    fn settle_front_on_an_empty_buffer_is_a_no_op() {
        let mut buffer: PendingBuffer<Vec<u8>> = PendingBuffer::new();
        let _ = buffer.settle_front(Ok::<(), ()>(()));
        assert!(buffer.is_empty());
        assert_eq!(buffer.bytes(), 0);
    }

    #[test]
    fn settle_front_hands_back_the_value_the_destination_returned() {
        let mut buffer = buffered(&[b"one\n"]);
        let settled = buffer.settle_front(Ok::<u32, ()>(7));
        assert_eq!(settled, Ok(7));
    }

    #[test]
    fn settle_all_on_acceptance_empties_the_buffer_and_zeroes_its_bytes() {
        let mut buffer = buffered(&[b"one\n", b"two\n", b"three\n"]);
        let settled = buffer.settle_all(Ok::<(), ()>(()));
        assert!(settled.is_ok());
        assert!(buffer.is_empty());
        assert_eq!(buffer.bytes(), 0);
    }

    #[test]
    fn settle_all_on_refusal_keeps_the_whole_batch_and_its_bytes() {
        let mut buffer = buffered(&[b"one\n", b"two\n", b"three\n"]);
        let settled = buffer.settle_all(Err::<(), &str>("refused"));
        assert_eq!(settled, Err("refused"));
        assert_eq!(
            entries(&buffer),
            [b"one\n".as_slice(), b"two\n", b"three\n"]
        );
        assert_eq!(buffer.bytes(), 4 + 4 + 6);
    }

    #[test]
    fn restore_front_puts_the_payloads_back_ahead_of_later_writes_in_order() {
        let mut buffer = buffered(&[b"later\n"]);
        let refused = buffered(&[b"first\n", b"second\n"]);
        let refused_bytes = refused.bytes();

        buffer.restore_front(refused);

        assert_eq!(
            entries(&buffer),
            [b"first\n".as_slice(), b"second\n", b"later\n"]
        );
        assert_eq!(buffer.bytes(), refused_bytes + 6);
    }

    #[test]
    fn restore_front_on_an_empty_buffer_restores_the_whole_batch() {
        let mut buffer: PendingBuffer<Vec<u8>> = PendingBuffer::new();
        let refused = buffered(&[b"one\n", b"two\n"]);
        let refused_bytes = refused.bytes();

        buffer.restore_front(refused);

        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.bytes(), refused_bytes);
    }

    #[test]
    fn restore_front_with_nothing_to_restore_leaves_the_buffer_untouched() {
        let mut buffer = buffered(&[b"one\n"]);
        buffer.restore_front(PendingBuffer::new());
        assert_eq!(entries(&buffer), [b"one\n".as_slice()]);
        assert_eq!(buffer.bytes(), 4);
    }

    #[test]
    fn a_restored_batch_still_triggers_the_flush_threshold_it_reached() {
        let mut buffer: PendingBuffer<Vec<u8>> = PendingBuffer::new();
        buffer.restore_front(buffered(&[b"0123456789\n"]));
        assert!(buffer.reached_threshold(11));
    }

    #[test]
    fn reached_threshold_is_false_below_the_threshold() {
        let buffer = buffered(&[b"0123456789\n"]);
        assert!(!buffer.reached_threshold(12));
        assert!(!PendingBuffer::<Vec<u8>>::new().reached_threshold(1));
    }

    #[test]
    fn reached_threshold_is_true_at_or_above_the_threshold() {
        let buffer = buffered(&[b"0123456789\n"]);
        assert!(buffer.reached_threshold(11));
        assert!(buffer.reached_threshold(5));
    }

    #[test]
    fn clamp_threshold_coerces_zero_to_one() {
        assert_eq!(clamp_threshold(0), 1);
    }

    #[test]
    fn clamp_threshold_passes_through_non_zero_values() {
        assert_eq!(clamp_threshold(1), 1);
        assert_eq!(clamp_threshold(1024), 1024);
        assert_eq!(clamp_threshold(usize::MAX), usize::MAX);
    }

    #[derive(Clone, Copy, Debug)]
    enum Op {
        PushRecord,
        AcceptHead,
        RefuseHead,
        AcceptBatch,
        RefuseBatch,
        RestoreTwo,
        RestoreNothing,
    }

    const EVERY_OP: [Op; 7] = [
        Op::PushRecord,
        Op::AcceptHead,
        Op::RefuseHead,
        Op::AcceptBatch,
        Op::RefuseBatch,
        Op::RestoreTwo,
        Op::RestoreNothing,
    ];

    fn apply(buffer: &mut PendingBuffer<Vec<u8>>, op: Op) {
        match op {
            Op::PushRecord => buffer.push_record(b"record\n"),
            Op::AcceptHead => drop(buffer.settle_front(Ok::<(), ()>(()))),
            Op::RefuseHead => drop(buffer.settle_front(Err::<(), ()>(()))),
            Op::AcceptBatch => drop(buffer.settle_all(Ok::<(), ()>(()))),
            Op::RefuseBatch => drop(buffer.settle_all(Err::<(), ()>(()))),
            Op::RestoreTwo => buffer.restore_front(buffered(&[b"a\n", b"bbb\n"])),
            Op::RestoreNothing => buffer.restore_front(PendingBuffer::new()),
        }
    }

    #[test]
    fn the_byte_count_matches_the_entries_after_every_sequence_of_three_operations() {
        for first in EVERY_OP {
            for second in EVERY_OP {
                for third in EVERY_OP {
                    let sequence = [first, second, third];
                    let mut buffer = PendingBuffer::new();
                    for op in sequence {
                        apply(&mut buffer, op);
                        assert_eq!(
                            buffer.bytes(),
                            summed_entry_bytes(&buffer),
                            "byte count desynced after {sequence:?}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(feature = "nats")]
    #[test]
    fn a_bytes_entry_is_tracked_the_same_as_a_vec_entry() {
        use bytes::Bytes;

        let mut buffer: PendingBuffer<Bytes> = PendingBuffer::new();
        buffer.push_record(b"one\n");
        buffer.push(Bytes::from_static(b"two\n"));
        assert_eq!(buffer.bytes(), 8);
        assert_eq!(buffer.front().map(Bytes::as_ref), Some(b"one\n".as_ref()));

        let _ = buffer.settle_front(Ok::<(), ()>(()));
        assert_eq!(buffer.bytes(), 4);
        assert_eq!(buffer.bytes(), summed_entry_bytes(&buffer));
    }
}
