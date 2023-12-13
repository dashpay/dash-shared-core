use std::collections::BTreeMap;
use hashes::hex::FromHex;
use crate::crypto::byte_util::{Reversable, UInt256};

#[test]
fn test_bytes_reverse_comparison() {

    let mut vec = vec![
        UInt256::from_hex("d2426992844e311149b2962f4ea991656ea5d1b36541e314e251915a6ffa1316").unwrap(),
        UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap(),
        UInt256::from_hex("631a5e99e59bab2bf06e4ec9874b3c3ced59187dc724c689ffa0fe99f2d3f210").unwrap(),
        UInt256::from_hex("113673823cf38eb56f30795d7f830b2d82b70a35b96812ad79d0889465b69df3").unwrap(),
        UInt256::from_hex("0e01a796d779a8494be44311d6daf07fdae8642b45a9b866024cd97d8dfd3545").unwrap(),
        UInt256::from_hex("feb146a52985cbf69f0a46b3a56f5f505538440bd42e993a0685a11fac1fdda5").unwrap(),
        UInt256::from_hex("48d665ade991114900349635c788775204057220728212e2b6b63e3545f67007").unwrap(),
        UInt256::from_hex("adcc454391d9f53e6fa523e047db5f335e38d9ead70dc8e4e648118c285d1d77").unwrap(),
        UInt256::from_hex("aadd2eac24d6cc9a0b439d3c9d5483b0ed64ebda21786760bb375efacd6e2a67").unwrap(),
        UInt256::from_hex("a90df0c30b2002a85cef6b695b986a3815c7dc82027c6896b7747258675a76da").unwrap(),
        UInt256::from_hex("e13fbad0ab0bca68cbcd4d68127de06037b4007c5acbe8550edcd60b7d4503e8").unwrap(),
        UInt256::from_hex("200ccffb2ef1da266efda63b35bc80bc8a547f29af3b8108f81ab222a1ceac35").unwrap(),
        UInt256::from_hex("21173e00737bac467d09effb15959d0459b853160805057a3975436d3e206591").unwrap(),
        UInt256::from_hex("321a1300b3ec63b3082d1626c7377d3c9e4e332eadefe12073f5e17b5099a49e").unwrap(),
    ];
    let map = vec.clone().into_iter().enumerate().map(|(i, key)| (key, i)).collect::<BTreeMap<_, _>>();

    // let sorted_map_values = vec![8, 0, 9, 5, 13, 4, 12, 11, 2, 7, 6, 10, 1, 3];
    let sorted_map_values = vec![3, 10, 9, 5, 13, 12, 7, 8, 4, 11, 0, 2, 6, 1];

    let sorted_vec = vec![
        UInt256::from_hex("113673823cf38eb56f30795d7f830b2d82b70a35b96812ad79d0889465b69df3").unwrap(),
        UInt256::from_hex("e13fbad0ab0bca68cbcd4d68127de06037b4007c5acbe8550edcd60b7d4503e8").unwrap(),
        UInt256::from_hex("a90df0c30b2002a85cef6b695b986a3815c7dc82027c6896b7747258675a76da").unwrap(),
        UInt256::from_hex("feb146a52985cbf69f0a46b3a56f5f505538440bd42e993a0685a11fac1fdda5").unwrap(),
        UInt256::from_hex("321a1300b3ec63b3082d1626c7377d3c9e4e332eadefe12073f5e17b5099a49e").unwrap(),
        UInt256::from_hex("21173e00737bac467d09effb15959d0459b853160805057a3975436d3e206591").unwrap(),
        UInt256::from_hex("adcc454391d9f53e6fa523e047db5f335e38d9ead70dc8e4e648118c285d1d77").unwrap(),
        UInt256::from_hex("aadd2eac24d6cc9a0b439d3c9d5483b0ed64ebda21786760bb375efacd6e2a67").unwrap(),
        UInt256::from_hex("0e01a796d779a8494be44311d6daf07fdae8642b45a9b866024cd97d8dfd3545").unwrap(),
        UInt256::from_hex("200ccffb2ef1da266efda63b35bc80bc8a547f29af3b8108f81ab222a1ceac35").unwrap(),
        UInt256::from_hex("d2426992844e311149b2962f4ea991656ea5d1b36541e314e251915a6ffa1316").unwrap(),
        UInt256::from_hex("631a5e99e59bab2bf06e4ec9874b3c3ced59187dc724c689ffa0fe99f2d3f210").unwrap(),
        UInt256::from_hex("48d665ade991114900349635c788775204057220728212e2b6b63e3545f67007").unwrap(),
        UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap()
    ];

    let sorted_map_keys = vec![
        UInt256::from_hex("0e01a796d779a8494be44311d6daf07fdae8642b45a9b866024cd97d8dfd3545").unwrap(),
        UInt256::from_hex("113673823cf38eb56f30795d7f830b2d82b70a35b96812ad79d0889465b69df3").unwrap(),
        UInt256::from_hex("200ccffb2ef1da266efda63b35bc80bc8a547f29af3b8108f81ab222a1ceac35").unwrap(),
        UInt256::from_hex("21173e00737bac467d09effb15959d0459b853160805057a3975436d3e206591").unwrap(),
        UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap(),
        UInt256::from_hex("321a1300b3ec63b3082d1626c7377d3c9e4e332eadefe12073f5e17b5099a49e").unwrap(),
        UInt256::from_hex("48d665ade991114900349635c788775204057220728212e2b6b63e3545f67007").unwrap(),
        UInt256::from_hex("631a5e99e59bab2bf06e4ec9874b3c3ced59187dc724c689ffa0fe99f2d3f210").unwrap(),
        UInt256::from_hex("a90df0c30b2002a85cef6b695b986a3815c7dc82027c6896b7747258675a76da").unwrap(),
        UInt256::from_hex("aadd2eac24d6cc9a0b439d3c9d5483b0ed64ebda21786760bb375efacd6e2a67").unwrap(),
        UInt256::from_hex("adcc454391d9f53e6fa523e047db5f335e38d9ead70dc8e4e648118c285d1d77").unwrap(),
        UInt256::from_hex("d2426992844e311149b2962f4ea991656ea5d1b36541e314e251915a6ffa1316").unwrap(),
        UInt256::from_hex("e13fbad0ab0bca68cbcd4d68127de06037b4007c5acbe8550edcd60b7d4503e8").unwrap(),
        UInt256::from_hex("feb146a52985cbf69f0a46b3a56f5f505538440bd42e993a0685a11fac1fdda5").unwrap(),
    ];

    println!("vec: {:?}", vec);
    println!("map: {:?}", map);
    vec.sort_by(|s1, s2| s2.reversed().cmp(&s1.reversed()));
    assert_eq!(vec, sorted_vec, "Sort incorrect");
    let map_keys = map.clone().into_keys().collect::<Vec<_>>();
    print!("map_keys: {:?}", map_keys);
    assert_eq!(map_keys, sorted_map_keys, "Sort BTreeMap keys incorrect");


    let mut v = Vec::from_iter(map.clone());
    v.sort_by(|(s1, _), (s2, _b)| s2.reversed().cmp(&s1.reversed()));
    let map_values1 = v.into_iter().map(|(s, node)| node).collect::<Vec<_>>();
    assert_eq!(map_values1, sorted_map_values, "Sort BTreeMap values 1 incorrect");


    let map_values2 = map.clone()
        .into_iter()
        .map(|(s, node)| (std::cmp::Reverse(s.reversed()), node))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(_, node)| node)
        .collect::<Vec<_>>();

    assert_eq!(map_values2, sorted_map_values, "Sort BTreeMap values 2 incorrect");

    let mut map_values3: Vec<_> = map.clone().into_iter().map(|(s, node)| (s.reversed(), node)).collect();
    map_values3.sort_unstable_by_key(|(s, _)| std::cmp::Reverse(*s));
    let map_values3: Vec<_> = map_values3.into_iter().map(|(_, node)| node).collect();
    assert_eq!(map_values3, sorted_map_values, "Sort BTreeMap values 3 incorrect");


    let mut v4: Vec<_> = map.clone().into_iter().collect::<Vec<_>>();
    v4.sort_unstable_by_key(|(s, _)| std::cmp::Reverse(s.reversed()));
    let v4 = v4.into_iter().map(|(_, node)| node).collect::<Vec<_>>();
    assert_eq!(v4, sorted_map_values, "Sort BTreeMap values 4 incorrect");


    // let mut map_values4: Vec<_> = map.into_iter().map(|(s, node)| (s.reversed(), node)).collect();
    // map_values4.sort_unstable_by_key(|(s, _)| std::cmp::Reverse(*s));
    // assert_eq!(map_values4, sorted_map_values, "Sort BTreeMap values 4 incorrect");
}

#[test]
fn test_any() {
    let vec = vec![
        UInt256::from_hex("d2426992844e311149b2962f4ea991656ea5d1b36541e314e251915a6ffa1316").unwrap(),
        UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap(),
        UInt256::from_hex("631a5e99e59bab2bf06e4ec9874b3c3ced59187dc724c689ffa0fe99f2d3f210").unwrap(),
        UInt256::from_hex("113673823cf38eb56f30795d7f830b2d82b70a35b96812ad79d0889465b69df3").unwrap(),
        UInt256::from_hex("0e01a796d779a8494be44311d6daf07fdae8642b45a9b866024cd97d8dfd3545").unwrap(),
        UInt256::from_hex("feb146a52985cbf69f0a46b3a56f5f505538440bd42e993a0685a11fac1fdda5").unwrap(),
        UInt256::from_hex("48d665ade991114900349635c788775204057220728212e2b6b63e3545f67007").unwrap(),
        UInt256::from_hex("adcc454391d9f53e6fa523e047db5f335e38d9ead70dc8e4e648118c285d1d77").unwrap(),
        UInt256::from_hex("aadd2eac24d6cc9a0b439d3c9d5483b0ed64ebda21786760bb375efacd6e2a67").unwrap(),
        UInt256::from_hex("a90df0c30b2002a85cef6b695b986a3815c7dc82027c6896b7747258675a76da").unwrap(),
        UInt256::from_hex("e13fbad0ab0bca68cbcd4d68127de06037b4007c5acbe8550edcd60b7d4503e8").unwrap(),
        UInt256::from_hex("200ccffb2ef1da266efda63b35bc80bc8a547f29af3b8108f81ab222a1ceac35").unwrap(),
        UInt256::from_hex("21173e00737bac467d09effb15959d0459b853160805057a3975436d3e206591").unwrap(),
        UInt256::from_hex("321a1300b3ec63b3082d1626c7377d3c9e4e332eadefe12073f5e17b5099a49e").unwrap(),
    ];

    assert!(vec.iter().any(|node| *node == UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap()));
    assert!(!vec.iter().any(|node| *node == UInt256::from_hex("ffc14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap()));
}
