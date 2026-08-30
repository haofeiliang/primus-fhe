use std::sync::Arc;

use primus_data::{Data, DataMut, DataOwned};

const VALUES: [u64; 4] = [1, 2, 3, 4];

fn assert_read<D: Data<Elem = u64>>(data: &D) {
    assert_eq!(data.as_slice(), VALUES);
    assert_eq!(data.len(), VALUES.len());
    assert!(!data.is_empty());
    assert_eq!(data.iter().copied().sum::<u64>(), 10);
    assert_eq!(data.split_at(2), VALUES.split_at(2));
}

fn assert_write<D: DataMut<Elem = u64>>(data: &mut D) {
    data.copy_from_slice(&VALUES);
    let (left, right) = data.split_at_mut(2);
    left.reverse();
    right.fill(0);
    assert_eq!(data.as_slice(), &[2, 1, 0, 0]);
}

fn collect_owned<D: DataOwned<Elem = u64>>() -> D {
    VALUES.into_iter().collect()
}

#[test]
fn standard_backends() {
    let vec = VALUES.to_vec();
    let boxed = VALUES.to_vec().into_boxed_slice();
    let arc: Arc<[u64]> = Arc::from(VALUES);
    let slice: &[u64] = &VALUES;
    let array_ref: &[u64; 4] = &VALUES;

    assert_read(&vec);
    assert_read(&boxed);
    assert_read(&arc);
    assert_read(&VALUES);
    assert_read(&slice);
    assert_read(&array_ref);

    assert_write(&mut VALUES.to_vec());
    assert_write(&mut VALUES.to_vec().into_boxed_slice());

    let mut array = VALUES;
    assert_write(&mut array);

    let mut slice_storage = VALUES;
    let mut slice: &mut [u64] = &mut slice_storage;
    assert_write(&mut slice);

    let mut array_storage = VALUES;
    let mut array_ref: &mut [u64; 4] = &mut array_storage;
    assert_write(&mut array_ref);
}

#[test]
fn owned_backends() {
    let vec = Vec::<u64>::from_slice(&VALUES);
    assert_eq!(vec.into_iter().collect::<Vec<_>>(), VALUES);

    let boxed = Box::<[u64]>::from_vec(VALUES.to_vec());
    assert_eq!(boxed.into_iter().collect::<Vec<_>>(), VALUES);

    let collected: Vec<u64> = collect_owned();
    assert_eq!(collected.as_slice(), VALUES);
}

#[cfg(feature = "aligned-vec")]
#[test]
fn aligned_backends() {
    use aligned_vec::{AVec, RuntimeAlign};

    let mut vec = AVec::<u64, RuntimeAlign>::from_slice(64, &VALUES);
    assert_eq!(vec.as_ptr().align_offset(64), 0);
    assert_read(&vec);
    assert_write(&mut vec);

    let mut boxed = AVec::<u64, RuntimeAlign>::from_slice(64, &VALUES).into_boxed_slice();
    assert_read(&boxed);
    assert_write(&mut boxed);
}
