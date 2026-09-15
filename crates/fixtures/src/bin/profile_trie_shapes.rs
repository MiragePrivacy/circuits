//! Profiles canonical receipt-trie proof shapes over sequential transaction
//! indices. This is an optimization tool, not a network collector.

use mirage_fixtures::trie::{key_for, Trie};

fn main() {
    let mut counts: Vec<usize> = (1..=512).collect();
    for boundary in [1024usize, 2048, 4096, 8192, 16_384, 32_768, 65_536] {
        for delta in -2isize..=2 {
            let count = boundary.saturating_add_signed(delta);
            if count > 0 && count <= 65_536 {
                counts.push(count);
            }
        }
    }
    counts.sort_unstable();
    counts.dedup();

    let value = vec![0x42; 432];
    let mut global_depth = 0usize;
    let mut global_position = Vec::<usize>::new();
    let mut witnesses = Vec::<(usize, usize, usize, usize)>::new();

    for count in counts {
        let values = vec![value.clone(); count];
        let trie = Trie::build(&values);
        let mut count_depth = 0usize;
        let mut count_position = Vec::<usize>::new();
        for index in 0..count {
            let proof = trie.proof(&key_for(index)).expect("proof");
            count_depth = count_depth.max(proof.len());
            // The final node is the constructed leaf and is not an ancestor
            // witness in the optimized relation.
            for (position, node) in proof[..proof.len() - 1].iter().enumerate() {
                if count_position.len() <= position {
                    count_position.resize(position + 1, 0);
                }
                count_position[position] = count_position[position].max(node.len());
                if global_position.len() <= position {
                    global_position.resize(position + 1, 0);
                }
                if node.len() > global_position[position] {
                    global_position[position] = node.len();
                    witnesses.push((position, node.len(), count, index));
                }
            }
        }
        if count_depth > global_depth {
            global_depth = count_depth;
            eprintln!("new depth {global_depth} at receipt count {count}");
        }
        if count <= 20 || matches!(count, 127..=130 | 255..=258 | 510..=512) {
            eprintln!("count {count:>5}: depth {count_depth}, ancestors {count_position:?}");
        }
    }

    println!("max proof depth: {global_depth}");
    println!("max ancestor bytes by position: {global_position:?}");
    println!("maxima witnesses (position, bytes, receipt_count, tx_index):");
    for witness in witnesses {
        println!("  {witness:?}");
    }
}
