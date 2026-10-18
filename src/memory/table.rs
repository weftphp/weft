//! A fixed-capacity hash table in shared memory, readable and writable by every process
//! forked after its creation.
//!
//! Rows hold a key (up to `max_key` bytes) and typed columns. Lookups and updates of
//! existing rows run in parallel under a shared table lock plus a per-row spinlock; inserts
//! and deletes take the table lock exclusively. Open addressing with linear probing keeps
//! everything in one mapping, so the table cannot grow after creation.

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::shared::Mapping;
use crate::core::{Error, ErrorKind, Result};
use crate::lock::{RwLock, SpinLock};

/// The type of a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Int,
    Float,
    /// A byte string of at most this many bytes.
    Bytes(usize),
}

/// A column definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub kind: ColumnType,
}

impl Column {
    pub fn new(name: &str, kind: ColumnType) -> Column {
        Column {
            name: name.to_owned(),
            kind,
        }
    }
}

/// A column value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
}

/// A copy of one row's values, in column order.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    names: Vec<String>,
    pub values: Vec<Value>,
}

impl Row {
    pub fn get(&self, column: &str) -> Option<&Value> {
        self.names
            .iter()
            .position(|n| n == column)
            .map(|i| &self.values[i])
    }

    pub fn int(&self, column: &str) -> Option<i64> {
        match self.get(column)? {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn float(&self, column: &str) -> Option<f64> {
        match self.get(column)? {
            Value::Float(n) => Some(*n),
            _ => None,
        }
    }

    pub fn bytes(&self, column: &str) -> Option<&[u8]> {
        match self.get(column)? {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

const EMPTY: u32 = 0;
const USED: u32 = 1;
const DELETED: u32 = 2;

/// Lives at the start of the mapping.
#[repr(C)]
struct Header {
    lock: RwLock,
    _pad: u32,
    count: AtomicU64,
}

/// Starts every row.
#[repr(C)]
struct RowHeader {
    lock: SpinLock,
    state: AtomicU32,
    key_len: AtomicU32,
    _pad: u32,
}

#[derive(Debug, Clone)]
struct Layout {
    name: String,
    kind: ColumnType,
    offset: usize,
}

const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// See the [module documentation](self).
pub struct Table {
    map: Mapping,
    columns: Vec<Layout>,
    slots: usize,
    capacity: usize,
    max_key: usize,
    row_size: usize,
    rows_offset: usize,
    hasher: RandomState,
}

impl Table {
    /// Creates a table for up to `capacity` rows with keys up to `max_key` bytes.
    pub fn new(columns: &[Column], capacity: usize, max_key: usize) -> Result<Table> {
        if capacity == 0 || max_key == 0 || columns.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "a table needs columns, capacity and a key size",
            ));
        }
        let mut offset = align8(std::mem::size_of::<RowHeader>() + max_key);
        let mut layout = Vec::with_capacity(columns.len());
        for column in columns {
            if layout.iter().any(|l: &Layout| l.name == column.name) {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    format!("duplicate column {}", column.name),
                ));
            }
            layout.push(Layout {
                name: column.name.clone(),
                kind: column.kind,
                offset,
            });
            offset += match column.kind {
                ColumnType::Int | ColumnType::Float => 8,
                ColumnType::Bytes(max) => align8(4 + max),
            };
        }
        let row_size = offset;
        // Keep the load factor at or below 80% so probe chains stay short.
        let slots = (capacity + capacity / 4 + 1).next_power_of_two();
        let rows_offset = align8(std::mem::size_of::<Header>()).max(64);
        let bytes = slots
            .checked_mul(row_size)
            .and_then(|n| n.checked_add(rows_offset))
            .ok_or_else(|| Error::new(ErrorKind::TooLarge, "table too large"))?;
        Ok(Table {
            map: Mapping::new(bytes)?,
            columns: layout,
            slots,
            capacity,
            max_key,
            row_size,
            rows_offset,
            hasher: RandomState::new(),
        })
    }

    fn header(&self) -> &Header {
        // SAFETY: the mapping starts with a zeroed (valid) Header and is page-aligned.
        unsafe { &*self.map.as_ptr().cast::<Header>() }
    }

    fn row_ptr(&self, slot: usize) -> *mut u8 {
        // SAFETY: slot < self.slots, so the row lies inside the mapping.
        unsafe {
            self.map
                .as_ptr()
                .add(self.rows_offset + slot * self.row_size)
        }
    }

    fn row_header(&self, slot: usize) -> &RowHeader {
        // SAFETY: each row starts 8-byte aligned with a zeroed (valid) RowHeader made only of
        // atomics, so shared references are sound.
        unsafe { &*self.row_ptr(slot).cast::<RowHeader>() }
    }

    fn key_ptr(&self, slot: usize) -> *mut u8 {
        // SAFETY: the key area follows the row header inside the row.
        unsafe { self.row_ptr(slot).add(std::mem::size_of::<RowHeader>()) }
    }

    /// The row's key. Caller holds the row lock.
    fn key_matches(&self, slot: usize, key: &[u8]) -> bool {
        let header = self.row_header(slot);
        if header.key_len.load(Ordering::Relaxed) as usize != key.len() {
            return false;
        }
        // SAFETY: under the row lock nobody writes the key; key_len <= max_key bytes exist.
        let stored = unsafe { std::slice::from_raw_parts(self.key_ptr(slot), key.len()) };
        stored == key
    }

    fn check_key(&self, key: &[u8]) -> Result<()> {
        if key.is_empty() || key.len() > self.max_key {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                format!("keys must be 1-{} bytes", self.max_key),
            ));
        }
        Ok(())
    }

    fn home(&self, key: &[u8]) -> usize {
        self.hasher.hash_one(key) as usize & (self.slots - 1)
    }

    /// Finds the slot holding `key`. Caller holds the table lock (shared or exclusive).
    /// Returns the slot with its row lock held.
    fn find(&self, key: &[u8]) -> Option<(usize, crate::lock::SpinGuard<'_>)> {
        let mut slot = self.home(key);
        for _ in 0..self.slots {
            let header = self.row_header(slot);
            let guard = header.lock.lock();
            match header.state.load(Ordering::Acquire) {
                EMPTY => return None,
                USED if self.key_matches(slot, key) => return Some((slot, guard)),
                _ => {}
            }
            drop(guard);
            slot = (slot + 1) & (self.slots - 1);
        }
        None
    }

    fn column(&self, name: &str) -> Result<&Layout> {
        self.columns
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("no column {name}")))
    }

    /// Writes one value. Caller holds the row lock.
    fn write_value(&self, slot: usize, column: &Layout, value: &Value) -> Result<()> {
        // SAFETY (all arms): the column lies inside the row, and the row lock gives this
        // process exclusive access to the row's bytes.
        let at = unsafe { self.row_ptr(slot).add(column.offset) };
        match (column.kind, value) {
            (ColumnType::Int, Value::Int(n)) => unsafe { at.cast::<i64>().write(*n) },
            (ColumnType::Float, Value::Float(n)) => unsafe { at.cast::<f64>().write(*n) },
            (ColumnType::Float, Value::Int(n)) => unsafe { at.cast::<f64>().write(*n as f64) },
            (ColumnType::Bytes(max), Value::Bytes(data)) => {
                if data.len() > max {
                    return Err(Error::new(
                        ErrorKind::TooLarge,
                        format!("column {} holds at most {max} bytes", column.name),
                    ));
                }
                // SAFETY: the column reserves 4 + `max` bytes and `data.len() <= max`; the row
                // lock gives exclusive access.
                unsafe {
                    at.cast::<u32>().write(data.len() as u32);
                    std::ptr::copy_nonoverlapping(data.as_ptr(), at.add(4), data.len());
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidArgument,
                    format!("wrong value type for column {}", column.name),
                ));
            }
        }
        Ok(())
    }

    /// Reads one value. Caller holds the row lock.
    fn read_value(&self, slot: usize, column: &Layout) -> Value {
        // SAFETY (all arms): as in `write_value`; the row lock excludes writers.
        let at = unsafe { self.row_ptr(slot).add(column.offset) };
        match column.kind {
            ColumnType::Int => Value::Int(unsafe { at.cast::<i64>().read() }),
            ColumnType::Float => Value::Float(unsafe { at.cast::<f64>().read() }),
            ColumnType::Bytes(max) => {
                let len = (unsafe { at.cast::<u32>().read() } as usize).min(max);
                Value::Bytes(unsafe { std::slice::from_raw_parts(at.add(4), len) }.to_vec())
            }
        }
    }

    fn read_row(&self, slot: usize) -> Row {
        Row {
            names: self.columns.iter().map(|c| c.name.clone()).collect(),
            values: self
                .columns
                .iter()
                .map(|c| self.read_value(slot, c))
                .collect(),
        }
    }

    /// Sets the given columns of `key`'s row, inserting the row (other columns zero) if it
    /// does not exist.
    pub fn set(&self, key: impl AsRef<[u8]>, values: &[(&str, Value)]) -> Result<()> {
        let key = key.as_ref();
        self.check_key(key)?;
        let columns = values
            .iter()
            .map(|(name, value)| Ok((self.column(name)?, value)))
            .collect::<Result<Vec<_>>>()?;
        {
            let _shared = self.header().lock.read();
            if let Some((slot, _row)) = self.find(key) {
                for (column, value) in &columns {
                    self.write_value(slot, column, value)?;
                }
                return Ok(());
            }
        }
        let _exclusive = self.header().lock.write();
        let (slot, _row) = match self.find(key) {
            Some(found) => found,
            None => self.insert(key)?,
        };
        for (column, value) in &columns {
            self.write_value(slot, column, value)?;
        }
        Ok(())
    }

    /// Claims a slot for a new key. Caller holds the table lock exclusively.
    fn insert(&self, key: &[u8]) -> Result<(usize, crate::lock::SpinGuard<'_>)> {
        let count = &self.header().count;
        if count.load(Ordering::Relaxed) as usize >= self.capacity {
            return Err(Error::new(ErrorKind::Full, "table is full"));
        }
        let mut slot = self.home(key);
        loop {
            let header = self.row_header(slot);
            let guard = header.lock.lock();
            if header.state.load(Ordering::Relaxed) != USED {
                // SAFETY: the row lock and the exclusive table lock give sole access.
                unsafe {
                    let header_len = std::mem::size_of::<RowHeader>();
                    std::ptr::write_bytes(
                        self.row_ptr(slot).add(header_len),
                        0,
                        self.row_size - header_len,
                    );
                    std::ptr::copy_nonoverlapping(key.as_ptr(), self.key_ptr(slot), key.len());
                }
                header.key_len.store(key.len() as u32, Ordering::Relaxed);
                header.state.store(USED, Ordering::Release);
                count.fetch_add(1, Ordering::Relaxed);
                return Ok((slot, guard));
            }
            drop(guard);
            slot = (slot + 1) & (self.slots - 1);
        }
    }

    /// A copy of `key`'s row.
    pub fn get(&self, key: impl AsRef<[u8]>) -> Option<Row> {
        let key = key.as_ref();
        self.check_key(key).ok()?;
        let _shared = self.header().lock.read();
        let (slot, _row) = self.find(key)?;
        Some(self.read_row(slot))
    }

    /// One column of `key`'s row.
    pub fn get_value(&self, key: impl AsRef<[u8]>, column: &str) -> Result<Option<Value>> {
        let key = key.as_ref();
        self.check_key(key)?;
        let column = self.column(column)?;
        let _shared = self.header().lock.read();
        Ok(self
            .find(key)
            .map(|(slot, _row)| self.read_value(slot, column)))
    }

    pub fn contains(&self, key: impl AsRef<[u8]>) -> bool {
        let key = key.as_ref();
        if self.check_key(key).is_err() {
            return false;
        }
        let _shared = self.header().lock.read();
        self.find(key).is_some()
    }

    /// Atomically adds `delta` to a numeric column (creating the row if needed) and returns
    /// the new value.
    pub fn incr(&self, key: impl AsRef<[u8]>, column: &str, delta: Value) -> Result<Value> {
        let key = key.as_ref();
        self.check_key(key)?;
        let layout = self.column(column)?;
        let apply = |slot: usize| -> Result<Value> {
            let updated = match (self.read_value(slot, layout), &delta) {
                (Value::Int(n), Value::Int(d)) => Value::Int(n.wrapping_add(*d)),
                (Value::Float(n), Value::Float(d)) => Value::Float(n + d),
                (Value::Float(n), Value::Int(d)) => Value::Float(n + *d as f64),
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidArgument,
                        format!("cannot increment column {column} by {delta:?}"),
                    ));
                }
            };
            self.write_value(slot, layout, &updated)?;
            Ok(updated)
        };
        {
            let _shared = self.header().lock.read();
            if let Some((slot, _row)) = self.find(key) {
                return apply(slot);
            }
        }
        let _exclusive = self.header().lock.write();
        let (slot, _row) = match self.find(key) {
            Some(found) => found,
            None => self.insert(key)?,
        };
        apply(slot)
    }

    /// Removes `key`'s row. Returns whether it existed.
    pub fn delete(&self, key: impl AsRef<[u8]>) -> bool {
        let key = key.as_ref();
        if self.check_key(key).is_err() {
            return false;
        }
        let _exclusive = self.header().lock.write();
        let Some((slot, row)) = self.find(key) else {
            return false;
        };
        let next = (slot + 1) & (self.slots - 1);
        // If the chain ends right after this row, it can become empty instead of a
        // tombstone, and so can tombstones just before it.
        let next_empty = self.row_header(next).state.load(Ordering::Acquire) == EMPTY;
        let header = self.row_header(slot);
        header
            .state
            .store(if next_empty { EMPTY } else { DELETED }, Ordering::Release);
        drop(row);
        if next_empty {
            let mut prev = slot;
            loop {
                prev = prev.wrapping_sub(1) & (self.slots - 1);
                let h = self.row_header(prev);
                let _g = h.lock.lock();
                if h.state.load(Ordering::Relaxed) != DELETED {
                    break;
                }
                h.state.store(EMPTY, Ordering::Release);
            }
        }
        self.header().count.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.header().count.load(Ordering::Relaxed) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes of shared memory the table occupies.
    pub fn memory_size(&self) -> usize {
        self.map.len()
    }

    /// A snapshot of every row. Rows changed during the walk may or may not be included.
    pub fn rows(&self) -> Vec<(Vec<u8>, Row)> {
        let _shared = self.header().lock.read();
        let mut out = Vec::with_capacity(self.len());
        for slot in 0..self.slots {
            let header = self.row_header(slot);
            let _row = header.lock.lock();
            if header.state.load(Ordering::Acquire) == USED {
                let len = header.key_len.load(Ordering::Relaxed) as usize;
                // SAFETY: the row lock excludes writers; len <= max_key.
                let key = unsafe { std::slice::from_raw_parts(self.key_ptr(slot), len) };
                out.push((key.to_vec(), self.read_row(slot)));
            }
        }
        out
    }

    /// Removes every row.
    pub fn clear(&self) {
        let _exclusive = self.header().lock.write();
        for slot in 0..self.slots {
            let header = self.row_header(slot);
            let _row = header.lock.lock();
            header.state.store(EMPTY, Ordering::Release);
        }
        self.header().count.store(0, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("len", &self.len())
            .field("capacity", &self.capacity)
            .field(
                "columns",
                &self.columns.iter().map(|c| &c.name).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(capacity: usize) -> Table {
        Table::new(
            &[
                Column::new("hits", ColumnType::Int),
                Column::new("score", ColumnType::Float),
                Column::new("name", ColumnType::Bytes(8)),
            ],
            capacity,
            16,
        )
        .unwrap()
    }

    #[test]
    fn set_get_incr_delete() {
        let t = table(8);
        t.set(
            "alice",
            &[
                ("hits", Value::Int(3)),
                ("name", Value::Bytes(b"Al".to_vec())),
            ],
        )
        .unwrap();
        let row = t.get("alice").unwrap();
        assert_eq!(row.int("hits"), Some(3));
        assert_eq!(row.float("score"), Some(0.0));
        assert_eq!(row.bytes("name"), Some(&b"Al"[..]));

        assert_eq!(
            t.incr("alice", "hits", Value::Int(2)).unwrap(),
            Value::Int(5)
        );
        assert_eq!(
            t.incr("bob", "score", Value::Float(1.5)).unwrap(),
            Value::Float(1.5)
        );
        assert_eq!(t.len(), 2);
        assert_eq!(
            t.get_value("bob", "score").unwrap(),
            Some(Value::Float(1.5))
        );

        let err = t
            .set("alice", &[("name", Value::Bytes(b"too long!".to_vec()))])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TooLarge);
        assert!(t.set("alice", &[("nope", Value::Int(1))]).is_err());
        assert!(t.set(&[b'k'; 17][..], &[]).is_err());

        assert!(t.delete("alice"));
        assert!(!t.delete("alice"));
        assert!(t.get("alice").is_none());
        assert_eq!(t.rows().len(), 1);
        t.clear();
        assert!(t.is_empty());
    }

    #[test]
    fn capacity_and_tombstones() {
        let t = table(16);
        for round in 0..20 {
            for i in 0..16 {
                t.set(format!("k{round}-{i}"), &[("hits", Value::Int(i))])
                    .unwrap();
            }
            assert_eq!(t.set("overflow", &[]).unwrap_err().kind(), ErrorKind::Full);
            for i in 0..16 {
                assert_eq!(t.get(format!("k{round}-{i}")).unwrap().int("hits"), Some(i));
                assert!(t.delete(format!("k{round}-{i}")));
            }
            assert!(t.is_empty());
        }
    }

    #[test]
    fn concurrent_increments() {
        let t = table(64);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for i in 0..500 {
                        t.incr(format!("key{}", i % 10), "hits", Value::Int(1))
                            .unwrap();
                    }
                });
            }
        });
        let total: i64 = t.rows().iter().filter_map(|(_, r)| r.int("hits")).sum();
        assert_eq!(total, 2000);
        assert_eq!(t.len(), 10);
    }
}
