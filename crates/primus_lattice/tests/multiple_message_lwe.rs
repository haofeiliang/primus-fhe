use primus_lattice::lwe::MultiMsgLwe;
use primus_modulus::NativeModulus;

#[test]
fn extract_all_matches_individual_rlwe_extraction() {
    let modulus = NativeModulus::new();

    for (dimension, bodies) in [(4, vec![10u32]), (4, vec![10, 11, 12, 13])] {
        let msg_count = bodies.len();
        let mut data: Vec<u32> = (1..=dimension as u32).collect();
        data.extend(bodies);
        let multi_message = MultiMsgLwe(data);

        let extracted = multi_message.extract_all(msg_count, modulus);
        assert_eq!(extracted.len(), msg_count);
        for (index, lwe) in extracted.iter().enumerate() {
            assert_eq!(
                lwe,
                &multi_message.extract_rlwe_mode(dimension, index, modulus)
            );
        }
    }

    let invalid = MultiMsgLwe(vec![1u32, 2, 3, 4]);
    assert!(std::panic::catch_unwind(|| invalid.extract_all(0, modulus)).is_err());
    assert!(std::panic::catch_unwind(|| invalid.extract_all(3, modulus)).is_err());
}
