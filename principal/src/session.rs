use std::{
    collections::{
        hash_map::{Drain, Entry, IntoIter, IntoKeys, IntoValues, Iter, IterMut, Keys, Values, ValuesMut},
        HashMap, TryReserveError,
    },
    fmt::{Display, Formatter, Result as FmtResult},
    hash::Hash,
    iter::{Extend, FromIterator, IntoIterator},
    net::IpAddr,
    ops::Index,
    panic::UnwindSafe,
};

/// Associated data about a principal. This is a map of ASCII case-insensitive strings to [SessionValue] values.
///
/// This wraps the standard Rust [HashMap] type, providing the case-insensitive key lookup and setting values to
/// the [SessionValue] type.
#[derive(Clone, Debug)]
pub struct SessionData {
    /// The variables associated with the session with the keys lower-cased.
    variables: HashMap<String, SessionValue>,
}

impl SessionData {
    /// Creates an empty HashMap.
    ///
    /// The underlying hash map is initially created with a capacity of 0, so it will not allocate until it is first
    /// inserted into.
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    /// Create a new session data object with a pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            variables: HashMap::with_capacity(capacity),
        }
    }

    /// Returns the number of elements the map can hold without reallocating.
    ///
    /// This number is a lower bound; the [SessionData] might be able to hold more, but is guaranteed to be able to
    /// hold at least this many.
    pub fn capacity(&self) -> usize {
        self.variables.capacity()
    }

    /// Clears the map, removing all key-value pairs. Keeps the allocated memory for reuse.
    pub fn clear(&mut self) {
        self.variables.clear();
    }

    /// Returns `true` if the map contains a value for the specified key.
    pub fn contains_key<Q: AsRef<str> + ?Sized>(&self, k: &Q) -> bool {
        self.variables.contains_key(&k.as_ref().to_lowercase())
    }

    /// Clears the map, returning all key-value pairs as an iterator. Keeps the allocated memory for reuse.
    ///
    /// If the returned iterator is dropped before being fully consumed, it drops the remaining key-value pairs. The
    /// returned iterator keeps a mutable borrow on the map to optimize its implementation.
    pub fn drain(&mut self) -> Drain<'_, String, SessionValue> {
        self.variables.drain()
    }

    /// Gets the given key’s corresponding entry in the map for in-place manipulation.
    pub fn entry<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Entry<'_, String, SessionValue> {
        self.variables.entry(key.as_ref().to_lowercase())
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<&SessionValue> {
        self.variables.get(&key.as_ref().to_lowercase())
    }

    /// Returns the key-value pair corresponding to the supplied key.
    pub fn get_key_value<Q: AsRef<str> + ?Sized>(&self, key: &Q) -> Option<(&str, &SessionValue)> {
        self.variables.get_key_value(&key.as_ref().to_lowercase()).map(|(key, value)| (key.as_str(), value))
    }

    /// Returns a mutable reference to the value corresponding to the key.
    pub fn get_mut<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<&mut SessionValue> {
        self.variables.get_mut(&key.as_ref().to_lowercase())
    }

    /// Inserts a key-value pair into the map.
    ///
    /// If the map did not have this key present, None is returned.
    /// If the map did have this key present, the value is updated, and the old value is returned.
    pub fn insert<Q: AsRef<str> + ?Sized>(&mut self, key: &Q, value: SessionValue) -> Option<SessionValue> {
        self.variables.insert(key.as_ref().to_lowercase(), value)
    }

    /// Creates a consuming iterator visiting all the keys in arbitrary order. The map cannot be used after calling
    /// this. The iterator element type is `String`.
    pub fn into_keys(self) -> IntoKeys<String, SessionValue> {
        self.variables.into_keys()
    }

    /// Creates a consuming iterator visiting all the values in arbitrary order. The map cannot be used after calling
    /// this. The iterator element type is `SessionValue`.
    pub fn into_values(self) -> IntoValues<String, SessionValue> {
        self.variables.into_values()
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The iterator element type is
    /// `(&'a String, &'a SessionData)`.
    pub fn iter(&self) -> Iter<'_, String, SessionValue> {
        self.variables.iter()
    }

    /// An iterator visiting all key-value pairs in arbitrary order, with mutable references to the values. The
    /// iterator element type is `(&'a String, &'a mut SessionValue)`.
    pub fn iter_mut(&mut self) -> IterMut<'_, String, SessionValue> {
        self.variables.iter_mut()
    }

    /// Returns `true` if the map contains no elements.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// An iterator visiting all keys in arbitrary order. The iterator element type is `&'a String`.
    pub fn keys(&self) -> Keys<'_, String, SessionValue> {
        self.variables.keys()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Removes a key from the map, returning the value at the key if the key was previously in the map.
    pub fn remove<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<SessionValue> {
        self.variables.remove(&key.as_ref().to_lowercase())
    }

    /// Removes a key from the map, returning the stored key and value if the key was previously in the map.
    pub fn remove_entry<Q: AsRef<str> + ?Sized>(&mut self, key: &Q) -> Option<(String, SessionValue)> {
        self.variables.remove_entry(&key.as_ref().to_lowercase())
    }

    /// Reserves capacity for at least `additional` more elements to be inserted in the `SessionData`. The collection
    /// may reserve more space to speculatively avoid frequent reallocations. After calling `reserve`, capacity will be
    /// greater than or equal to `self.len() + additional`. Does nothing if capacity is already sufficient.
    ///
    /// # Panics
    ///
    /// Panics if the new allocation size overflows [`usize`].
    pub fn reserve(&mut self, additional: usize) {
        self.variables.reserve(additional)
    }

    /// Retains only the elements specified by the predicate.
    ///
    /// In other words, remove all pairs `(k, v)` for which `f(&k, &mut v)` returns `false`. The elements are visited
    /// in unsorted (and unspecified) order.
    pub fn retain<F: FnMut(&str, &mut SessionValue) -> bool>(&mut self, mut f: F) {
        self.variables.retain(|key, value| f(key.as_str(), value))
    }

    /// Shrinks the capacity of the map with a lower limit. It will drop down no lower than the supplied limit while
    /// maintaining the internal rules and possibly leaving some space in accordance with the resize policy.
    ///
    /// If the current capacity is less than the lower limit, this is a no-op.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.variables.shrink_to(min_capacity)
    }

    /// Shrinks the capacity of the map as much as possible. It will drop down as much as possible while maintaining
    /// the internal rules and possibly leaving some space in accordance with the resize policy.
    pub fn shrink_to_fit(&mut self) {
        self.variables.shrink_to_fit()
    }

    /// Tries to reserve capacity for at least `additional` more elements to be inserted in the `SessionData`. The
    /// collection may reserve more space to speculatively avoid frequent reallocations. After calling `try_reserve`,
    /// capacity will be greater than or equal to `self.len() + additional` if it returns `Ok(())`. Does nothing if
    /// capacity is already sufficient.
    ///
    /// # Errors
    ///
    /// If the capacity overflows, or the allocator reports a failure, then an error is returned.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        self.variables.try_reserve(additional)
    }

    /// An iterator visiting all values in arbitrary order. The iterator element type is `&'a SessionValue`.
    pub fn values(&self) -> Values<'_, String, SessionValue> {
        self.variables.values()
    }

    /// An iterator visiting all values mutably in arbitrary order. The iterator element type is `&'a mut SessionValue`.
    pub fn values_mut(&mut self) -> ValuesMut<'_, String, SessionValue> {
        self.variables.values_mut()
    }
}

impl Default for SessionData {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, K: AsRef<str> + ?Sized> Extend<(&'a K, &'a SessionValue)> for SessionData {
    fn extend<T: IntoIterator<Item = (&'a K, &'a SessionValue)>>(&mut self, iter: T) {
        self.variables.extend(iter.into_iter().map(|(key, value)| (key.as_ref().to_lowercase(), value.clone())));
    }
}

impl From<HashMap<String, SessionValue>> for SessionData {
    fn from(variables: HashMap<String, SessionValue>) -> Self {
        let mut my_vars = HashMap::new();
        for (key, value) in variables.iter() {
            my_vars.insert(key.to_lowercase(), value.clone());
        }

        Self {
            variables: my_vars,
        }
    }
}

impl<K: AsRef<str>, const N: usize> From<[(K, SessionValue); N]> for SessionData {
    fn from(variables: [(K, SessionValue); N]) -> Self {
        let mut my_vars = HashMap::new();
        for (key, value) in variables.iter() {
            my_vars.insert(key.as_ref().to_lowercase(), value.clone());
        }

        Self {
            variables: my_vars,
        }
    }
}

impl<K: AsRef<str>> FromIterator<(K, SessionValue)> for SessionData {
    fn from_iter<T: IntoIterator<Item = (K, SessionValue)>>(iter: T) -> Self {
        let mut my_vars = HashMap::new();
        for (key, value) in iter {
            my_vars.insert(key.as_ref().to_lowercase(), value.clone());
        }

        Self {
            variables: my_vars,
        }
    }
}

impl<Q: AsRef<str> + ?Sized> Index<&'_ Q> for SessionData {
    type Output = SessionValue;

    fn index(&self, key: &Q) -> &Self::Output {
        self.variables.get(&key.as_ref().to_lowercase()).unwrap()
    }
}

impl<'a> IntoIterator for &'a SessionData {
    type Item = (&'a String, &'a SessionValue);
    type IntoIter = Iter<'a, String, SessionValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.variables.iter()
    }
}

impl<'a> IntoIterator for &'a mut SessionData {
    type Item = (&'a String, &'a mut SessionValue);
    type IntoIter = IterMut<'a, String, SessionValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.variables.iter_mut()
    }
}

impl IntoIterator for SessionData {
    type Item = (String, SessionValue);
    type IntoIter = IntoIter<String, SessionValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.variables.into_iter()
    }
}

impl UnwindSafe for SessionData {}

impl PartialEq for SessionData {
    fn eq(&self, other: &Self) -> bool {
        self.variables == other.variables
    }
}

impl PartialEq<HashMap<String, SessionValue>> for SessionData {
    fn eq(&self, other: &HashMap<String, SessionValue>) -> bool {
        if self.variables.len() != other.len() {
            return false;
        }

        for (key, other_value) in other.iter() {
            match self.variables.get(&key.to_lowercase()) {
                None => return false,
                Some(value) => {
                    if value != other_value {
                        return false;
                    }
                }
            }
        }

        true
    }
}

impl Eq for SessionData {}

/// Associated data about a session key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionValue {
    /// Null value
    Null,

    /// Boolean value.
    Bool(bool),

    /// Integer value.
    Integer(i64),

    /// IP address value.
    IpAddr(IpAddr),

    /// String value.
    String(String),
}

impl Display for SessionValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(b) => write!(f, "Bool({})", b),
            Self::Integer(i) => write!(f, "Integer({})", i),
            Self::IpAddr(ip) => write!(f, "IpAddr({})", ip),
            Self::String(s) => write!(f, "String({})", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{SessionData, SessionValue},
        std::{
            cmp::Ordering,
            collections::hash_map::{DefaultHasher, HashMap},
            hash::{Hash, Hasher},
            iter::IntoIterator,
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
        },
    };

    #[test]
    fn check_session_value_derived() {
        let sv1a = SessionValue::Null;
        let sv1b = SessionValue::Null;
        let sv2 = SessionValue::Bool(true);
        let values = vec![
            SessionValue::Null,
            SessionValue::Bool(false),
            SessionValue::Bool(true),
            SessionValue::Integer(-1),
            SessionValue::Integer(0),
            SessionValue::Integer(1),
            SessionValue::IpAddr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            SessionValue::IpAddr(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
            SessionValue::String("test1".to_string()),
            SessionValue::String("test2".to_string()),
        ];
        let display = vec![
            "Null",
            "Bool(false)",
            "Bool(true)",
            "Integer(-1)",
            "Integer(0)",
            "Integer(1)",
            "IpAddr(127.0.0.1)",
            "IpAddr(::1)",
            "String(test1)",
            "String(test2)",
        ];
        assert_eq!(sv1a, sv1b);
        assert_ne!(sv1a, sv2);
        assert_eq!(sv1a, sv1a.clone());

        // Ensure session values are hashable.
        let mut h1a = DefaultHasher::new();
        let mut h1b = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        sv1a.hash(&mut h1a);
        sv1b.hash(&mut h1b);
        sv2.hash(&mut h2);
        let hash1a = h1a.finish();
        let hash1b = h1b.finish();
        let hash2 = h2.finish();
        assert_eq!(hash1a, hash1b);
        assert_ne!(hash1a, hash2);

        // Ensure a logical ordering for session values.
        for i in 0..values.len() {
            for j in 0..values.len() {
                assert_eq!(values[i].cmp(&values[j]), i.cmp(&j));

                match i.cmp(&j) {
                    Ordering::Less => assert!(values[i] < values[j]),
                    Ordering::Equal => assert!(values[i] == values[j]),
                    Ordering::Greater => assert!(values[i] > values[j]),
                }
            }
        }

        // Ensure we can debug print session values.
        for ref value in values.iter() {
            let _ = format!("{:?}", value);
        }

        // Ensure the display matches
        for i in 0..values.len() {
            assert_eq!(values[i].to_string(), display[i]);
        }
    }

    #[test]
    fn check_case_sensitivity() {
        let mut sd = SessionData::new();
        assert!(sd.is_empty());
        sd.insert("test", SessionValue::Null);
        assert!(sd.contains_key("TEST"));
        assert!(sd.contains_key("test"));

        sd.insert("Test", SessionValue::Bool(true));
        sd.insert("TeST2", SessionValue::Integer(100));
        assert!(sd.contains_key("tEsT"));
        assert!(sd.contains_key("test"));

        assert_eq!(sd.len(), 2);
        assert!(!sd.is_empty());
        assert_eq!(sd.get("test"), Some(&SessionValue::Bool(true)));
        assert!(sd.contains_key("tEsT"));
        assert!(sd.contains_key("test"));
        assert_eq!(sd.get_key_value("tEST"), Some(("test", &SessionValue::Bool(true))));

        let sv = sd.get_mut("tesT");
        assert!(sv.is_some());
        *sv.unwrap() = SessionValue::String("Hello".to_string());
        assert_eq!(sd.get("test"), Some(&SessionValue::String("Hello".to_string())));

        sd.entry("test2").and_modify(|v| *v = SessionValue::Integer(200));
        assert_eq!(sd["test2"], SessionValue::Integer(200));

        assert!(sd.remove("teST").is_some());
        assert!(sd.remove("test").is_none());
        assert!(sd.remove_entry("test2").is_some());
    }

    #[test]
    fn check_clone_eq() {
        let mut sd1 = SessionData::new();
        sd1.insert("test", SessionValue::String("Hello World".to_string()));
        let sd2 = sd1.clone();
        assert_eq!(sd1, sd2);

        let mut sd3 = SessionData::with_capacity(1);
        assert!(sd3.capacity() > 0);
        sd3.insert("TEST", SessionValue::String("Hello World".to_string()));
        assert_eq!(sd1, sd3);
        sd3.drain();
        assert_ne!(sd1, sd3);
        sd3.insert("test", SessionValue::String("Hello again".to_string()));
        assert_ne!(sd1, sd3);
        sd3.insert("test", SessionValue::Integer(1));
        assert_ne!(sd1, sd3);
        sd3.clear();
        sd3.insert("TeST", SessionValue::String("Hello World".to_string()));
        assert_eq!(sd1, sd3);

        let mut h = HashMap::with_capacity(1);
        h.insert("test".to_string(), SessionValue::String("Hello World".to_string()));
        assert_eq!(sd1, h);
        h.drain();
        assert_ne!(sd1, h);
        h.insert("test".to_string(), SessionValue::String("Hello again".to_string()));
        assert_ne!(sd1, h);
        h.insert("test".to_string(), SessionValue::Integer(1));
        assert_ne!(sd1, h);
        h.insert("test".to_string(), SessionValue::String("Hello World".to_string()));
        assert_eq!(sd1, h);
        h.drain();
        h.insert("test2".to_string(), SessionValue::String("Hello World".to_string()));
        assert_ne!(sd1, h);

        sd1.clear();
        sd1.shrink_to_fit();
        assert_eq!(sd1.capacity(), 0);
        sd1.reserve(100);
        assert!(sd1.capacity() >= 100);
        sd1.shrink_to(50);
        assert!(sd1.capacity() >= 50);

        // Ensure we can debug print session data.
        let _ = format!("{:?}", sd1);
    }

    #[test]
    fn check_from_hashmap() {
        let mut h = HashMap::new();
        h.insert("Test".to_string(), SessionValue::String("Hello World".to_string()));
        let mut sd = SessionData::from(h);
        assert_eq!(sd.len(), 1);
        assert_eq!(sd["test"], SessionValue::String("Hello World".to_string()));

        let to_add = vec![("Test2", SessionValue::Integer(100)), ("Test3", SessionValue::Bool(true))];

        sd.extend(to_add.iter().map(|r| (r.0, &r.1)));
        assert_eq!(sd.len(), 3);
        assert_eq!(sd["test2"], SessionValue::Integer(100));
        assert_eq!(sd["test3"], SessionValue::Bool(true));
    }

    #[test]
    fn check_from_array() {
        let values: [(String, SessionValue); 3] = [
            ("Test".to_string(), SessionValue::String("Hello World".to_string())),
            ("Test2".to_string(), SessionValue::Integer(100)),
            ("Test3".to_string(), SessionValue::Bool(true)),
        ];
        let sd = SessionData::from(values);
        assert_eq!(sd.len(), 3);
        assert_eq!(sd["test"], SessionValue::String("Hello World".to_string()));
        assert_eq!(sd["test2"], SessionValue::Integer(100));
        assert_eq!(sd["test3"], SessionValue::Bool(true));
    }

    #[test]
    fn check_from_iter() {
        let values = vec![
            ("Test".to_string(), SessionValue::String("Hello World".to_string())),
            ("Test2".to_string(), SessionValue::Integer(100)),
            ("Test3".to_string(), SessionValue::Bool(true)),
        ];
        let sd = SessionData::from_iter(values);
        assert_eq!(sd.len(), 3);
        assert_eq!(sd["test"], SessionValue::String("Hello World".to_string()));
        assert_eq!(sd["test2"], SessionValue::Integer(100));
        assert_eq!(sd["test3"], SessionValue::Bool(true));
    }

    #[test]
    fn check_keys() {
        let mut sd: SessionData = Default::default();
        sd.try_reserve(3).unwrap();
        sd.insert("test1", SessionValue::Null);
        sd.insert("TEst2", SessionValue::Bool(true));
        sd.insert("tesT3", SessionValue::Integer(1));

        let mut test1_seen = false;
        let mut test2_seen = false;
        let mut test3_seen = false;
        for key in sd.keys() {
            match key.as_str() {
                "test1" => {
                    assert!(!test1_seen);
                    test1_seen = true;
                }
                "test2" => {
                    assert!(!test2_seen);
                    test2_seen = true;
                }
                "test3" => {
                    assert!(!test3_seen);
                    test3_seen = true;
                }
                _ => panic!("Unexpected key: {}", key),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        test1_seen = false;
        test2_seen = false;
        test3_seen = false;
        for key in sd.into_keys() {
            match key.as_str() {
                "test1" => {
                    assert!(!test1_seen);
                    test1_seen = true;
                }
                "test2" => {
                    assert!(!test2_seen);
                    test2_seen = true;
                }
                "test3" => {
                    assert!(!test3_seen);
                    test3_seen = true;
                }
                _ => panic!("Unexpected key: {}", key),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);
    }

    #[test]
    fn check_values() {
        let mut sd: SessionData = Default::default();
        sd.try_reserve(3).unwrap();
        sd.insert("test1", SessionValue::Null);
        sd.insert("TEst2", SessionValue::Bool(true));
        sd.insert("tesT3", SessionValue::Integer(1));

        let mut test1_seen = false;
        let mut test2_seen = false;
        let mut test3_seen = false;
        for value in sd.values_mut() {
            match value {
                SessionValue::Null => {
                    assert!(!test1_seen);
                    test1_seen = true;
                    *value = SessionValue::Integer(100);
                }
                SessionValue::Bool(true) => {
                    assert!(!test2_seen);
                    test2_seen = true;
                    *value = SessionValue::Integer(101);
                }
                SessionValue::Integer(1) => {
                    assert!(!test3_seen);
                    test3_seen = true;
                    *value = SessionValue::Integer(102);
                }
                _ => panic!("Unexpected value: {}", value),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        let mut test1_seen = false;
        let mut test2_seen = false;
        let mut test3_seen = false;
        for value in sd.values() {
            match value {
                SessionValue::Integer(100) => {
                    assert!(!test1_seen);
                    test1_seen = true
                }
                SessionValue::Integer(101) => {
                    assert!(!test2_seen);
                    test2_seen = true
                }
                SessionValue::Integer(102) => {
                    assert!(!test3_seen);
                    test3_seen = true
                }
                _ => panic!("Unexpected value: {}", value),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        test1_seen = false;
        test2_seen = false;
        test3_seen = false;
        for value in sd.into_values() {
            match value {
                SessionValue::Integer(100) => {
                    assert!(!test1_seen);
                    test1_seen = true
                }
                SessionValue::Integer(101) => {
                    assert!(!test2_seen);
                    test2_seen = true
                }
                SessionValue::Integer(102) => {
                    assert!(!test3_seen);
                    test3_seen = true
                }
                _ => panic!("Unexpected value: {}", value),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);
    }

    #[test]
    fn check_iter() {
        let mut sd: SessionData = Default::default();
        sd.try_reserve(3).unwrap();
        sd.insert("test1", SessionValue::Null);
        sd.insert("TEst2", SessionValue::Bool(true));
        sd.insert("tesT3", SessionValue::Integer(1));

        let mut test1_seen = false;
        let mut test2_seen = false;
        let mut test3_seen = false;
        for (key, value) in sd.iter_mut() {
            match key.as_str() {
                "test1" => {
                    assert_eq!(value, &SessionValue::Null);
                    assert!(!test1_seen);
                    *value = SessionValue::Integer(100);
                    test1_seen = true;
                }
                "test2" => {
                    assert_eq!(value, &SessionValue::Bool(true));
                    assert!(!test2_seen);
                    *value = SessionValue::Integer(101);
                    test2_seen = true;
                }
                "test3" => {
                    assert_eq!(value, &SessionValue::Integer(1));
                    assert!(!test3_seen);
                    *value = SessionValue::Integer(102);
                    test3_seen = true;
                }
                _ => panic!("Unexpected value: {}", value),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        let mut test1_seen = false;
        let mut test2_seen = false;
        let mut test3_seen = false;
        for (key, value) in sd.iter() {
            match key.as_str() {
                "test1" => {
                    assert_eq!(value, &SessionValue::Integer(100));
                    assert!(!test1_seen);
                    test1_seen = true;
                }
                "test2" => {
                    assert_eq!(value, &SessionValue::Integer(101));
                    assert!(!test2_seen);
                    test2_seen = true;
                }
                "test3" => {
                    assert_eq!(value, &SessionValue::Integer(102));
                    assert!(!test3_seen);
                    test3_seen = true;
                }
                _ => panic!("Unexpected key: {}", key),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        let mut sd_mut = sd.clone();

        test1_seen = false;
        test2_seen = false;
        test3_seen = false;
        for (key, value) in (&sd).into_iter() {
            match key.as_str() {
                "test1" => {
                    assert_eq!(value, &SessionValue::Integer(100));
                    assert!(!test1_seen);
                    test1_seen = true;
                }
                "test2" => {
                    assert_eq!(value, &SessionValue::Integer(101));
                    assert!(!test2_seen);
                    test2_seen = true;
                }
                "test3" => {
                    assert_eq!(value, &SessionValue::Integer(102));
                    assert!(!test3_seen);
                    test3_seen = true;
                }
                _ => panic!("Unexpected key: {}", key),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        test1_seen = false;
        test2_seen = false;
        test3_seen = false;
        for (key, value) in sd.into_iter() {
            match key.as_str() {
                "test1" => {
                    assert_eq!(value, SessionValue::Integer(100));
                    assert!(!test1_seen);
                    test1_seen = true;
                }
                "test2" => {
                    assert_eq!(value, SessionValue::Integer(101));
                    assert!(!test2_seen);
                    test2_seen = true;
                }
                "test3" => {
                    assert_eq!(value, SessionValue::Integer(102));
                    assert!(!test3_seen);
                    test3_seen = true;
                }
                _ => panic!("Unexpected key: {}", key),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(test3_seen);

        sd_mut.retain(|k, _| k != "test3");

        test1_seen = false;
        test2_seen = false;
        test3_seen = false;
        for (key, value) in (&mut sd_mut).into_iter() {
            match key.as_str() {
                "test1" => {
                    assert_eq!(value, &SessionValue::Integer(100));
                    assert!(!test1_seen);
                    test1_seen = true;
                }
                "test2" => {
                    assert_eq!(value, &SessionValue::Integer(101));
                    assert!(!test2_seen);
                    test2_seen = true;
                }
                _ => panic!("Unexpected key: {}", key),
            }
        }
        assert!(test1_seen);
        assert!(test2_seen);
        assert!(!test3_seen);
    }
}
// end tests -- do not delete; needed for coverage.
