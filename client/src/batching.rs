// Groups items into the fewest batches needed to cover them all, where
// items in the same batch sit at consecutive addresses. This is the shared
// shape behind every "batch contiguous Modbus addresses into one request"
// decision in this crate — register/coil polling reads (`polling.rs`) and
// register/coil transaction writes (`transaction_consumer.rs`) all reduced
// to this exact algorithm, just over different item types and different
// per-function-code size limits, so it was extracted here once that
// pattern had shown up for the fourth time (see the project's own
// extraction-based-programming convention: concrete duplication first,
// generalize only once the real shape is known).
//
// A gap in the address range always starts a new batch — nothing here
// reads (or writes, for the write-batching callers) an address that
// wasn't actually asked for, even if that means an extra request instead
// of one covering the gap.

#[derive(Debug, Clone, PartialEq)]
pub struct Batch<T> {
    pub starting_address: u16,
    pub items: Vec<T>,
}

impl<T> Batch<T> {
    pub fn quantity(&self) -> u16 {
        self.items.len() as u16
    }
}

/// Sorts `items` by `address_of` and groups consecutive addresses into
/// batches, capped at `max_batch_size` entries each.
pub fn build_batches<T>(
    mut items: Vec<T>,
    address_of: impl Fn(&T) -> u16,
    max_batch_size: u16,
) -> Vec<Batch<T>> {
    items.sort_by_key(|item| address_of(item));

    let mut batches: Vec<Batch<T>> = Vec::new();
    for item in items {
        let address = address_of(&item);
        let extends_last_batch = match batches.last() {
            Some(batch) => {
                let expected_next_address = batch.starting_address.wrapping_add(batch.quantity());
                address == expected_next_address && batch.quantity() < max_batch_size
            }
            None => false,
        };
        if extends_last_batch {
            batches.last_mut().unwrap().items.push(item);
        } else {
            batches.push(Batch {
                starting_address: address,
                items: vec![item],
            });
        }
    }
    batches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_items_are_grouped_into_one_batch() {
        let items = vec![(40001u16, "A"), (40002, "B"), (40003, "C")];
        let batches = build_batches(items, |(address, _)| *address, 125);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 40001);
        assert_eq!(batches[0].quantity(), 3);
    }

    #[test]
    fn a_gap_in_addresses_starts_a_new_batch() {
        let items = vec![(1u16, "A"), (10u16, "B")];
        let batches = build_batches(items, |(address, _)| *address, 125);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].starting_address, 1);
        assert_eq!(batches[1].starting_address, 10);
    }

    #[test]
    fn items_are_grouped_regardless_of_input_order() {
        let items = vec![(2u16, "B"), (1u16, "A")];
        let batches = build_batches(items, |(address, _)| *address, 125);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].starting_address, 1);
        assert_eq!(
            batches[0]
                .items
                .iter()
                .map(|(_, name)| *name)
                .collect::<Vec<_>>(),
            vec!["A", "B"]
        );
    }

    #[test]
    fn a_batch_never_exceeds_the_given_max_size() {
        let items: Vec<(u16, usize)> = (0..130).map(|offset| (1 + offset as u16, offset)).collect();
        let batches = build_batches(items, |(address, _)| *address, 125);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].quantity(), 125);
        assert_eq!(batches[1].quantity(), 5);
    }

    #[test]
    fn an_empty_input_produces_no_batches() {
        let items: Vec<(u16, &str)> = vec![];
        let batches = build_batches(items, |(address, _)| *address, 125);
        assert!(batches.is_empty());
    }
}
