// CEP:FILE: hot/src/vm_value.rs
// CEP:WHAT: The tagged machine value type and heap cell layout shared by the interpreter and the emitted code.
// CEP:WHY: One fixed-width tagged representation keeps interpreter slots, heap cells, and guard snapshots byte-compatible, so deoptimization is a memcpy, not a translation.
// CEP:CLASS: CEP-0
// CEP:STATUS: complete
// CEP:FAILURE: none; value construction is total and cannot fail.
// CEP:ASSUMES: layout is tag-plus-payload with CELL_BYTES stride; enforced by static assertions here and layout tests in tests.
// CEP:COST: every access is a register-width move; no allocation, no dispatch.
// CEP:EVIDENCE: unit test ssl-tests::unit_value_layout; differential tests interpreter versus JIT.
#![allow(clippy::result_unit_err)]

/// Type tag for nil values.
pub const TAG_NIL: u64 = 0;
/// Type tag for boolean values.
pub const TAG_BOOL: u64 = 1;
/// Type tag for integer values (small ints, dual-number style).
pub const TAG_INT: u64 = 2;
/// Type tag for double values.
pub const TAG_NUM: u64 = 3;
/// Type tag for interned string handles.
pub const TAG_STR: u64 = 4;
/// Type tag for heap table handles.
pub const TAG_TBL: u64 = 5;

/// Number of value bytes per heap cell and per frame slot.
pub const VALUE_BYTES: u32 = 16;

/// Tagged value stored inline in interpreter slots and heap cells.
#[derive(Copy, Clone, PartialEq, Debug)]
#[repr(C)]
pub struct SslValue {
    /// Tag word selecting the payload interpretation.
    pub tag: u64,
    /// Payload word: int bits, double bits, bool, or handle.
    pub payload: u64,
}

impl SslValue {
    pub const fn nil() -> SslValue {
        SslValue {
            tag: TAG_NIL,
            payload: 0,
        }
    }

    pub const fn boolean(value: bool) -> SslValue {
        SslValue {
            tag: TAG_BOOL,
            payload: value as u64,
        }
    }

    pub const fn integer(value: i64) -> SslValue {
        SslValue {
            tag: TAG_INT,
            payload: value as u64,
        }
    }

    pub const fn number(value: f64) -> SslValue {
        SslValue {
            tag: TAG_NUM,
            payload: value.to_bits(),
        }
    }

    pub const fn string(handle: u32) -> SslValue {
        SslValue {
            tag: TAG_STR,
            payload: handle as u64,
        }
    }

    pub const fn table(handle: u32) -> SslValue {
        SslValue {
            tag: TAG_TBL,
            payload: handle as u64,
        }
    }

    pub const fn is_nil(&self) -> bool {
        self.tag == TAG_NIL
    }

    pub const fn is_int(&self) -> bool {
        self.tag == TAG_INT
    }

    pub const fn is_num(&self) -> bool {
        self.tag == TAG_NUM
    }

    pub const fn is_table(&self) -> bool {
        self.tag == TAG_TBL
    }

    pub const fn is_truthy(&self) -> bool {
        if self.tag == TAG_NIL {
            return false;
        }
        if self.tag == TAG_BOOL {
            return self.payload != 0;
        }
        true
    }

    pub const fn as_int(&self) -> i64 {
        self.payload as i64
    }

    pub const fn as_num(&self) -> f64 {
        f64::from_bits(self.payload)
    }

    pub const fn as_handle(&self) -> u32 {
        self.payload as u32
    }
}

const _: () = assert!(core::mem::size_of::<SslValue>() as u32 == VALUE_BYTES);
